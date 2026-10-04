using System.Net.Http.Headers;
using System.Net.Http.Json;
using ModelContextProtocol;
using OpenEtradeMcp.Contracts;

namespace OpenEtradeMcp.Server;

public sealed record AdapterConnections(HttpClient Authorization, HttpClient Gateway) : IDisposable
{ public void Dispose() { Authorization.Dispose(); Gateway.Dispose(); } }

public sealed class GatewayAdapter(IHttpContextAccessor accessor, AdapterConnections connections) : IDisposable
{
    private readonly HttpClient auth = connections.Authorization;
    private readonly HttpClient gateway = connections.Gateway;
    public async Task<string> ReadAsync(ReadRequest request)
    {
        RequestPolicy.Validate(request);
        var ctx = accessor.HttpContext ?? throw new McpException("Authorization required.");
        using var issue = new HttpRequestMessage(HttpMethod.Post, "/internal/assertions") { Content = JsonContent.Create(new AssertionRequest(request)) };
        issue.Headers.Authorization = AuthenticationHeaderValue.Parse(ctx.Request.Headers.Authorization.ToString());
        using var issued = await auth.SendAsync(issue, ctx.RequestAborted);
        if (!issued.IsSuccessStatusCode) throw new McpException("Read authorization denied or unavailable.");
        var assertion = (await issued.Content.ReadFromJsonAsync<AssertionReply>(ctx.RequestAborted)) ?? throw new McpException("Read authorization unavailable.");
        // Fresh request: the external bearer is never copied to the gateway client or message.
        using var result = await gateway.PostAsJsonAsync("/internal/read", new GatewayRequest(request, assertion.Assertion), ctx.RequestAborted);
        if (!result.IsSuccessStatusCode) throw new McpException("Read unavailable. Owner may need to reauthorize.");
        var body = await result.Content.ReadAsStringAsync(ctx.RequestAborted);
        if (body.Length > 2 * 1024 * 1024) throw new McpException("Read response exceeds limit.");
        return body;
    }
    public async Task<bool> AuthenticateAsync(HttpContext ctx)
    {
        if (!AuthenticationHeaderValue.TryParse(ctx.Request.Headers.Authorization, out var bearer) || bearer.Scheme != "Bearer" || string.IsNullOrEmpty(bearer.Parameter)) return false;
        using var message = new HttpRequestMessage(HttpMethod.Post, "/internal/validate") { Headers = { Authorization = bearer } };
        using var response = await auth.SendAsync(message, ctx.RequestAborted);
        return response.IsSuccessStatusCode;
    }
    public void Dispose() { /* Connections are owned by the DI singleton. */ }
}
