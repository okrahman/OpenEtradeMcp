using ModelContextProtocol.Server;
using OpenEtradeMcp.Contracts;
using OpenEtradeMcp.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
// This process deliberately has no reference to the brokerage/OAuth assembly.
if (builder.Configuration.AsEnumerable().Any(x => x.Key.Contains("Sandbox", StringComparison.OrdinalIgnoreCase) && x.Value != null))
    throw new InvalidOperationException("Legacy brokerage configuration is forbidden in the adapter.");
InternalTls.Listen(builder);
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton(sp => new AdapterConnections(InternalTls.Client(builder.Configuration, "authorization", "AuthorizationUrl"), InternalTls.Client(builder.Configuration, "gateway", "GatewayUrl")));
builder.Services.AddSingleton<GatewayAdapter>();
builder.Services.AddMcpServer().WithHttpTransport(o => o.Stateless = true).WithTools<ReadTools>();
var app = builder.Build();
InternalTls.SafeErrors(app);
app.Use(async (ctx, next) => {
    if (!InternalTls.Allowed(ctx, "ingress")) { ctx.Response.StatusCode = 403; return; }
    if (ctx.Request.Path.StartsWithSegments("/mcp"))
    {
        if (ctx.Request.Headers.Origin.Count > 0 && ctx.Request.Headers.Origin != builder.Configuration.Required("PublicOrigin"))
        { ctx.Response.StatusCode = 403; return; }
        if (!await ctx.RequestServices.GetRequiredService<GatewayAdapter>().AuthenticateAsync(ctx))
        {
            SecurityEvent.Write("policy_denied");
            ctx.Response.StatusCode = 401;
            ctx.Response.Headers.WWWAuthenticate = "Bearer resource_metadata=\"" + builder.Configuration.Required("PublicOrigin") + "/.well-known/oauth-protected-resource\"";
            return;
        }
    }
    if (ctx.Request.Path == "/mcp" && ctx.Request.Method == "POST")
    {
        // The SDK's deserializer otherwise accepts duplicate JSON member names.
        ctx.Request.EnableBuffering();
        var json = await StrictJson.ReadAsync<System.Text.Json.JsonElement>(ctx.Request.Body, ctx.RequestAborted);
        ctx.Request.Body.Position = 0;
        if (json.ValueKind == System.Text.Json.JsonValueKind.Object && json.TryGetProperty("method", out var method) && method.GetString() == "tools/call")
        {
            var parameters = json.GetProperty("params"); var name = parameters.GetProperty("name").GetString();
            if (!Enum.TryParse<ReadOperation>(name, out var operation) || name != operation.ToString() || !Enum.IsDefined(operation))
            { SecurityEvent.Write("policy_denied"); ctx.Response.StatusCode = 403; return; }
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            if (parameters.TryGetProperty("arguments", out var arguments))
                foreach (var argument in arguments.EnumerateObject())
                {
                    if (!RequestPolicy.Rules[operation].Parameters.Any(p => p.Name == argument.Name)) throw new PolicyException();
                    var value = argument.Value;
                    if (value.ValueKind == System.Text.Json.JsonValueKind.Null) continue;
                    if (value.ValueKind is not (System.Text.Json.JsonValueKind.String or System.Text.Json.JsonValueKind.Number or System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False)) throw new PolicyException();
                    values.Add(argument.Name, value.ValueKind == System.Text.Json.JsonValueKind.String ? value.GetString()! : value.GetRawText());
                }
            RequestPolicy.Validate(new ReadRequest(1, operation, values));
        }
    }
    await next(ctx);
});
app.MapMcp("/mcp");
await app.RunAsync();

namespace OpenEtradeMcp.Server { public sealed class ServerEntryPoint { } }
