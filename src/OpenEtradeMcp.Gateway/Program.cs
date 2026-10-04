using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using OpenEtradeMcp;
using OpenEtradeMcp.Contracts;
using OpenEtradeMcp.Gateway;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
if (config.AsEnumerable().Any(x => x.Key.Contains("Sandbox", StringComparison.OrdinalIgnoreCase) && x.Value != null))
    throw new InvalidOperationException("Legacy sandbox configuration is forbidden.");
InternalTls.Listen(builder); builder.Logging.ClearProviders();
var key = RSA.Create(); key.ImportFromPem(File.ReadAllText(config.Required("AssertionPublicKey")));
builder.Services.AddSingleton(new Assertions(key, config.Required("Issuer")));
builder.Services.AddSingleton<ReadLimits>();
var fixtures = config.GetValue<bool>("Fixtures");
EncryptedFileTokenStore? store = null;
EtradeOAuth1AuthenticationHandler? auth = null;
HttpClient? business = null;
if (!fixtures)
{
    var etrade = new ETradeConfig { ConsumerKey = File.ReadAllText(config.Required("ConsumerKeyFile")).Trim(),
        ConsumerSecret = File.ReadAllText(config.Required("ConsumerSecretFile")).Trim(), TokenKeyFile = config.Required("TokenKeyFile"), TokenDirectory = config.Required("TokenDirectory") };
    if (etrade.ConsumerKey.Length == 0 || etrade.ConsumerSecret.Length == 0) throw new InvalidOperationException("Production credentials required.");

    store = new(etrade);
    var oauth = new HttpClient(new ReadOnlyGuard(etrade, true) { InnerHandler = BrokerageTransport.Create(config) }) { Timeout = TimeSpan.FromSeconds(30) };
    auth = new(oauth, etrade, store); await auth.InitializeAsync();
    business = new HttpClient(new TransmissionPolicy { InnerHandler = new ReadOnlyGuard(etrade, false, auth) {
        InnerHandler = BrokerageTransport.Create(config) } }) { Timeout = TimeSpan.FromSeconds(30), MaxResponseContentBufferSize = 2 * 1024 * 1024 };
}
else if (new[] { "ConsumerKeyFile", "ConsumerSecretFile", "TokenKeyFile" }.Any(k => config[k] != null)) throw new InvalidOperationException("Fixture deployment must not mount production credentials.");
var app = builder.Build(); InternalTls.SafeErrors(app);
app.Lifetime.ApplicationStopped.Register(() => { business?.Dispose(); store?.Dispose(); key.Dispose(); });
app.Use(async (ctx, next) => {
    if (ctx.Request.Headers.Authorization.Count != 0) { ctx.Response.StatusCode = 400; return; }
    var permitted = ctx.Request.Path == "/internal/read" ? InternalTls.Allowed(ctx, "mcp") : InternalTls.Allowed(ctx, "authorization");
    if (!permitted) { ctx.Response.StatusCode = 403; return; } await next(ctx);
    if (ctx.Response.StatusCode >= 400) SecurityEvent.Write("policy_denied");
});
app.MapPost("/internal/read", async (HttpContext ctx, Assertions assertions, ReadLimits limits) => {
    var input = await StrictJson.ReadAsync<GatewayRequest>(ctx.Request.Body, ctx.RequestAborted);
    RequestPolicy.Validate(input.Request); var principal = assertions.Verify(input.Assertion, input.Request);
    using var lease = limits.TryAcquire(principal.FindFirstValue("agent")!);
    if (lease == null) return Results.StatusCode(429);
    using var authorize = InternalTls.Client(config, "authorization", "AuthorizationUrl");
    // Independent policy and signature checks, followed by online single-use consumption immediately before dispatch.
    var uri = RequestPolicy.Route(input.Request);
    using var message = new HttpRequestMessage(HttpMethod.Get, uri); message.Headers.Accept.ParseAdd("application/json");
    RequestPolicy.ValidateOutgoing(message);
    using var consumed = await authorize.PostAsJsonAsync("/internal/consume", new ConsumeRequest(input.Assertion), ctx.RequestAborted);
    if (!consumed.IsSuccessStatusCode) return Results.Unauthorized();
    if (fixtures) return Results.Json(new { fixture = true, operation = input.Request.Operation.ToString(), data = Array.Empty<object>() });
    try {
        using var response = await business!.SendAsync(message, ctx.RequestAborted);
        if (!response.IsSuccessStatusCode) return Results.Json(new { error = "brokerage_read_unavailable" }, statusCode: 502);
        var content = await response.Content.ReadAsStringAsync(ctx.RequestAborted);
        // Provider error responses and headers never propagate to agents.
        using var document = JsonDocument.Parse(content);
        return Results.Content(document.RootElement.GetRawText(), "application/json");
    } catch (EtradeOperationException) { SecurityEvent.Write("reauthorization_required"); return Results.Json(new { error = "owner_reauthorization_required" }, statusCode: 503); }
});
app.MapGet("/admin/status", () => Results.Json(new { production = true, fixtures, authenticated = auth?.IsAuthenticated ?? false,
    expiresAt = auth?.Session.ExpiresAt, recovery = auth?.Session.RecoveryStatus ?? "fixtures" }));
app.MapPost("/admin/start", async () => fixtures ? Results.BadRequest() : Results.Json(new { authorizationUrl = await auth!.StartAsync() }));
app.MapPost("/admin/complete", async (HttpContext ctx) => {
    if (fixtures) return Results.BadRequest();
    var input = await StrictJson.ReadAsync<Completion>(ctx.Request.Body, ctx.RequestAborted);
    await auth!.CompleteAsync(input.Verifier); return Results.Ok();
});
app.MapPost("/admin/revoke", async () => { if (!fixtures) await auth!.RevokeAsync(); return Results.Ok(); });
await app.RunAsync();
public sealed record Completion(string Verifier);
