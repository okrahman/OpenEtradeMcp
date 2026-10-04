using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using OpenEtradeMcp.Contracts;
namespace OpenEtradeMcp.Authorization;

public sealed record ClientEnrollment(string ClientId, string PlatformIdentity, string[] RedirectUris, string AuthMethod,
    string? MetadataUrl, bool IsolatedConnection);
public sealed record ClientDocument(string ClientId, string[] RedirectUris, string AuthMethod, string Hash);
public sealed class Cimd(IConfiguration config)
{
    public static bool PublicAddress(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return false;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return !(b[0] is 0 or 10 or 127 || b[0] >= 224 || b[0] == 169 && b[1] == 254 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 ||
                b[0] == 192 && b[1] == 168 || b[0] == 100 && b[1] >= 64 && b[1] <= 127 ||
                b[0] == 192 && b[1] == 0 || b[0] == 198 && b[1] is 18 or 19 ||
                b[0] == 198 && b[1] == 51 && b[2] == 100 || b[0] == 203 && b[1] == 0 && b[2] == 113);
        // Only global unicast; exclude documentation and mapped/translated IPv4 ranges.
        return b[0] >= 0x20 && b[0] <= 0x3f && !(b[0] == 0x20 && b[1] == 0x01 && (b[2] < 2 || b[2] == 0x0d && b[3] == 0xb8));
    }
    public static Uri ExactHttps(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo != "" ||
            uri.Fragment != "" || IPAddress.TryParse(uri.Host, out _) || uri.HostNameType != UriHostNameType.Dns || uri.AbsoluteUri != value)
            throw new PolicyException();
        return uri;
    }
    public async Task<ClientDocument> FetchAsync(string url, CancellationToken ct)
    {
        var uri = ExactHttps(url);
        if (!(config.GetSection("CimdDestinations").Get<string[]>() ?? []).Contains(url, StringComparer.Ordinal)) throw new PolicyException();
        // Proxy also checks destination DNS addresses and TLS SNI. Fetcher checks again for SSRF.
        // Resolution and address pinning occur exclusively in the restricted proxy.
        using var handler = new RestrictedIdentityHandler(config);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode != HttpStatusCode.OK) throw new PolicyException();
        var document = await StrictJson.ReadAsync<JsonElement>(await response.Content.ReadAsStreamAsync(ct), ct);
        var allowed = new[] { "client_id", "client_name", "redirect_uris", "token_endpoint_auth_method", "grant_types", "response_types", "scope" };
        if (document.EnumerateObject().Any(p => !allowed.Contains(p.Name))) throw new PolicyException();
        var id = document.GetProperty("client_id").GetString()!;
        if (id != url) throw new PolicyException();
        var redirects = document.GetProperty("redirect_uris").EnumerateArray().Select(e => e.GetString()!).ToArray();
        foreach (var redirect in redirects) ExactHttps(redirect);
        if (redirects.Length is < 1 or > 10 || redirects.Distinct(StringComparer.Ordinal).Count() != redirects.Length) throw new PolicyException();
        var method = document.TryGetProperty("token_endpoint_auth_method", out var m) ? m.GetString()! : "none";
        if (method != "none") throw new PolicyException(); // Key-source authentication awaits explicit implementation and approval.
        if (document.TryGetProperty("grant_types", out var g) && g.EnumerateArray().Any(v => v.GetString() is not ("authorization_code" or "refresh_token"))) throw new PolicyException();
        if (document.TryGetProperty("response_types", out var r) && r.EnumerateArray().Any(v => v.GetString() != "code")) throw new PolicyException();
        if (document.TryGetProperty("scope", out var scope) && scope.GetString() != "etrade.read offline_access") throw new PolicyException();
        var hash = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { id, redirects = redirects.Order(StringComparer.Ordinal), method })));
        return new(id, redirects, method, hash);
    }
}
