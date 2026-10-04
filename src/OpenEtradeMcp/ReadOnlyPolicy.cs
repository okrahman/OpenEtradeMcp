using Microsoft.OpenApi.Readers;
using Microsoft.OpenApi.Models;
using System.Text.RegularExpressions;

namespace OpenEtradeMcp;

public static class ReadOnlyPolicy
{
    public static readonly IReadOnlyDictionary<string, (string Method, string Path)> Operations =
        new Dictionary<string, (string, string)>
        {
            ["listAccounts"] = ("GET", "/accounts/list"),
            ["getAccountBalance"] = ("GET", "/accounts/{accountIdKey}/balance"),
            ["getPortfolio"] = ("GET", "/accounts/{accountIdKey}/portfolio"),
            ["listTransactions"] = ("GET", "/accounts/{accountIdKey}/transactions"),
            ["getTransactionDetails"] = ("GET", "/accounts/{accountIdKey}/transactions/{transactionId}"),
            ["getQuotes"] = ("GET", "/market/quote/{symbols}"),
            ["lookupProduct"] = ("GET", "/market/lookup/{search}"),
            ["getOptionChains"] = ("GET", "/market/optionchains"),
            ["getOptionExpireDates"] = ("GET", "/market/optionexpiredate"),
            ["listOrders"] = ("GET", "/accounts/{accountIdKey}/orders")
        };

    public static OpenApiDocument Filter(string specification)
    {
        var document = new OpenApiStringReader().Read(specification, out var diagnostic);
        if (diagnostic.Errors.Count != 0) throw new EtradeOperationException("Invalid API specification.");
        foreach (var path in document.Paths.ToArray())
        {
            foreach (var operation in path.Value.Operations.ToArray())
                if (!Operations.TryGetValue(operation.Value.OperationId ?? "", out var allowed) ||
                    allowed.Path != path.Key || allowed.Method != operation.Key.ToString().ToUpperInvariant())
                    path.Value.Operations.Remove(operation.Key);
            if (path.Value.Operations.Count == 0) document.Paths.Remove(path.Key);
        }
        return document;
    }

    public static void Validate(HttpRequestMessage request, ETradeConfig config, bool oauth)
    {
        var uri = request.RequestUri!;
        if (uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo != "" || uri.Fragment != "")
            throw new EtradeOperationException("Request blocked by read-only policy.");
        if (oauth)
        {
            const string method = "GET";
            if (uri.Host == "api.etrade.com" && request.Method.Method == method &&
                new[] { "/oauth/request_token", "/oauth/access_token", "/oauth/renew_access_token", "/oauth/revoke_access_token" }.Contains(uri.AbsolutePath)) return;
        }
        else if (uri.Host == "api.etrade.com" &&
            !Uri.UnescapeDataString(uri.AbsolutePath).Contains('\\') &&
            Uri.UnescapeDataString(uri.AbsolutePath).Split('/').Length == uri.AbsolutePath.Split('/').Length)
        {
            foreach (var route in Operations.Values)
            {
                var pattern = "^/v1" + string.Join("/", route.Path.Split('/').Select(segment =>
                    segment.StartsWith('{') ? "[^/]+" : Regex.Escape(segment))) + "(?:\\.json)?$";
                if (request.Method.Method == route.Method && Regex.IsMatch(uri.AbsolutePath, pattern)) return;
            }
        }
        throw new EtradeOperationException("Request blocked by read-only policy.");
    }
}

public sealed class ReadOnlyGuard(ETradeConfig config, bool oauth, EtradeOAuth1AuthenticationHandler? authentication = null) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ReadOnlyPolicy.Validate(request, config, oauth);
        if (oauth) return await base.SendAsync(request, cancellationToken);
        return await authentication!.SendBusinessAsync(request, () => base.SendAsync(request, cancellationToken));
    }
}
