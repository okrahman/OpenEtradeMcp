using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace OpenEtradeMcp.Contracts;

[JsonConverter(typeof(JsonStringEnumConverter<ReadOperation>))]
public enum ReadOperation
{
    listAccounts, getAccountBalance, getPortfolio, listTransactions, getTransactionDetails,
    getQuotes, lookupProduct, getOptionChains, getOptionExpireDates, listOrders
}
public sealed record ReadRequest(int Version, ReadOperation Operation, Dictionary<string, string> Arguments)
{
    public string Digest() => Convert.ToHexString(SHA256.HashData(CanonicalBytes()));
    public byte[] CanonicalBytes()
    {
        RequestPolicy.Validate(this);
        return JsonSerializer.SerializeToUtf8Bytes(new { version = Version, operation = Operation.ToString(),
            arguments = new SortedDictionary<string, string>(Arguments, StringComparer.Ordinal) });
    }
}
public sealed class PolicyException : Exception { public PolicyException() : base("Read request denied.") { } }
public static class StrictJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16
    };
    public static T Parse<T>(byte[] bytes)
    {
        if (bytes.Length > 32768) throw new PolicyException();
        using var doc = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
        Check(doc.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, Options) ?? throw new PolicyException();
    }
    private static void Check(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in node.EnumerateObject()) { if (!names.Add(p.Name)) throw new PolicyException(); Check(p.Value); }
        }
        if (node.ValueKind == JsonValueKind.Array) foreach (var value in node.EnumerateArray()) Check(value);
    }
    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var bytes = new byte[4096]; int count;
        while ((count = await stream.ReadAsync(bytes, ct)) != 0)
        {
            if (buffer.Length + count > 32768) throw new PolicyException();
            buffer.Write(bytes, 0, count);
        }
        return Parse<T>(buffer.ToArray());
    }
}
public static class RequestPolicy
{
    public sealed record Rule(string Operation, string Path, Parameter[] Parameters);
    public sealed record Parameter(string Name, string Location, bool Required, string Type, string[] Values,
        double? Minimum, double? Maximum, string? Pattern);
    public static readonly IReadOnlyDictionary<ReadOperation, Rule> Rules = Load();
    private static IReadOnlyDictionary<ReadOperation, Rule> Load()
    {
        using var stream = typeof(RequestPolicy).Assembly.GetManifestResourceStream("OpenEtradeMcp.Contracts.operations.json")!;
        return JsonSerializer.Deserialize<Rule[]>(stream, new JsonSerializerOptions(JsonSerializerDefaults.Web))!
            .ToDictionary(r => Enum.Parse<ReadOperation>(r.Operation));
    }
    public static void Validate(ReadRequest r)
    {
        if (r.Version != 1 || !Rules.TryGetValue(r.Operation, out var rule) || r.Arguments == null || r.Arguments.Count > 20)
            throw new PolicyException();
        foreach (var p in rule.Parameters.Where(p => p.Required)) if (!r.Arguments.ContainsKey(p.Name)) throw new PolicyException();
        foreach (var (name, value) in r.Arguments)
        {
            var p = rule.Parameters.SingleOrDefault(p => p.Name == name) ?? throw new PolicyException();
            if (string.IsNullOrWhiteSpace(value) || value.Length > 256 || value.Any(char.IsControl) ||
                value.Contains('%') || value.Contains('\\') || value.Contains('/') || value is "." or "..") throw new PolicyException();
            if (p.Location == "path" && !Regex.IsMatch(value, "^[A-Za-z0-9_,. :+@-]+$", RegexOptions.CultureInvariant)) throw new PolicyException();
            if (p.Values.Length > 0 && !p.Values.Contains(value, StringComparer.Ordinal)) throw new PolicyException();
            if (p.Type == "boolean" && value is not ("true" or "false")) throw new PolicyException();
            if (p.Type is "number" or "integer")
            {
                if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var n) || !double.IsFinite(n) ||
                    (p.Type == "integer" && (!long.TryParse(value, out _) || n < 0)) ||
                    n < (p.Minimum ?? 0) || n > (p.Maximum ?? (p.Location == "path" ? long.MaxValue : 1000000))) throw new PolicyException();
            }
            if (p.Pattern != null && !Regex.IsMatch(value, p.Pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50))) throw new PolicyException();
        }
    }
    public static Uri Route(ReadRequest r)
    {
        Validate(r); var rule = Rules[r.Operation]; var path = rule.Path;
        foreach (var p in rule.Parameters.Where(p => p.Location == "path")) path = path.Replace("{" + p.Name + "}", Uri.EscapeDataString(r.Arguments[p.Name]));
        var query = rule.Parameters.Where(p => p.Location == "query" && r.Arguments.ContainsKey(p.Name))
            .OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => Uri.EscapeDataString(p.Name) + "=" + Uri.EscapeDataString(r.Arguments[p.Name]));
        return new Uri("https://api.etrade.com/v1" + path + ".json" + (query.Any() ? "?" + string.Join("&", query) : ""));
    }
    public static void ValidateOutgoing(HttpRequestMessage message)
    {
        var uri = message.RequestUri ?? throw new PolicyException();
        if (uri.Scheme != "https" || uri.Host != "api.etrade.com" || !uri.IsDefaultPort || uri.UserInfo != "" || uri.Fragment != "" ||
            message.Method != HttpMethod.Get || message.Content != null) throw new PolicyException();
        var route = Rules.Values.SingleOrDefault(r => Regex.IsMatch(uri.AbsolutePath,
            "^/v1" + string.Join("/", r.Path.Split('/').Select(s => s.StartsWith('{') ? "[^/]+" : Regex.Escape(s))) + @"\.json$"));
        if (route == null) throw new PolicyException();
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        var segments = uri.AbsolutePath[3..^5].Split('/'); var expected = route.Path.Split('/');
        for (int i = 0; i < expected.Length; i++) if (expected[i].StartsWith('{')) args.Add(expected[i][1..^1], Uri.UnescapeDataString(segments[i]));
        if (uri.Query.Length > 1)
            foreach (var part in uri.Query[1..].Split('&'))
            {
                var pair = part.Split('=');
                if (pair.Length != 2 || !args.TryAdd(Uri.UnescapeDataString(pair[0]), Uri.UnescapeDataString(pair[1]))) throw new PolicyException();
            }
        var r = new ReadRequest(1, Enum.Parse<ReadOperation>(route.Operation), args);
        if (Route(r).AbsoluteUri != uri.AbsoluteUri) throw new PolicyException();
    }
}
public sealed record AssertionRequest(ReadRequest Request);
public sealed record GatewayRequest(ReadRequest Request, string Assertion);
public sealed record AssertionReply(string Assertion);
public sealed record TokenStatus(string AgentId, string GrantId, string ClientId, string TokenId);
public sealed record ConsumeRequest(string Assertion);
