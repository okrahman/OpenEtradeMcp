using Microsoft.AspNetCore;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenEtradeMcp.Authorization;
using OpenEtradeMcp.Contracts;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
var provision = args.Contains("--provision-owner");
if (!provision) InternalTls.Listen(builder);
builder.Logging.ClearProviders(); // Redacted audit events are persisted; HTTP tokens, query strings and bodies are never logged.
builder.Services.AddDbContext<State>(o => { o.UseSqlite("Data Source=" + config.Required("StateFile")); o.UseOpenIddict(); });
builder.Services.AddIdentity<Owner, IdentityRole>(o => { o.SignIn.RequireConfirmedAccount = true; o.Lockout.MaxFailedAccessAttempts = 5; })
    .AddEntityFrameworkStores<State>().AddDefaultTokenProviders();
builder.Services.ConfigureApplicationCookie(o => {
    o.Cookie.Name = "__Host-owner"; o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.SameSite = SameSiteMode.Lax;
    o.ExpireTimeSpan = TimeSpan.FromHours(1); o.SlidingExpiration = false;
    o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = 403; return Task.CompletedTask; };
});
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(config.Required("DataProtectionDirectory")))
    .ProtectKeysWithCertificate(X509CertificateLoader.LoadPkcs12FromFile(config.Required("TokenEncryptionCertificate"), null))
    .SetApplicationName("OpenEtradeMcp.Authorization");
builder.Services.AddAuthentication().AddGoogle(o => {
    o.ClientId = config.Required("GoogleClientId"); o.ClientSecret = File.ReadAllText(config.Required("GoogleClientSecretFile")).Trim();
    o.SignInScheme = IdentityConstants.ExternalScheme; o.CallbackPath = "/owner/google-callback";
    o.BackchannelHttpHandler = new RestrictedIdentityHandler(config);
});
builder.Services.AddOpenIddict().AddCore(o => o.UseEntityFrameworkCore().UseDbContext<State>()).AddServer(o => {
    o.SetIssuer(new Uri(config.Required("Issuer")));
    o.SetAuthorizationEndpointUris("/connect/authorize").SetTokenEndpointUris("/connect/token");
    o.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow().RequireProofKeyForCodeExchange();
    o.RegisterScopes("etrade.read", Scopes.OfflineAccess); o.RegisterResources(config.Required("Resource"));
    o.SetAccessTokenLifetime(TimeSpan.FromMinutes(5)); o.SetRefreshTokenLifetime(TimeSpan.FromDays(30));
    o.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(2)); o.DisableSlidingRefreshTokenExpiration();
    o.Configure(v => v.RefreshTokenReuseLeeway = TimeSpan.Zero);
    o.AddSigningCertificate(X509CertificateLoader.LoadPkcs12FromFile(config.Required("TokenSigningCertificate"), null));
    o.AddEncryptionCertificate(X509CertificateLoader.LoadPkcs12FromFile(config.Required("TokenEncryptionCertificate"), null));
    o.UseAspNetCore().EnableAuthorizationEndpointPassthrough().EnableTokenEndpointPassthrough();
    // The certificate authenticates ingress to this service; it is not an OAuth client's certificate.
    o.RemoveEventHandler(OpenIddictServerAspNetCoreHandlers.ExtractClientCertificate<OpenIddictServerEvents.ExtractTokenRequestContext>.Descriptor);
    o.AddEventHandler<OpenIddictServerEvents.ProcessAuthenticationContext>(h => h.SetOrder(int.MinValue + 100000).UseInlineHandler(async ctx => {
        // Reject redeemed reference refresh tokens before OpenIddict's normal validation; revoke the agent grant as well.
        if (!ctx.Request.IsRefreshTokenGrantType() || string.IsNullOrEmpty(ctx.Request.RefreshToken)) return;
        var manager = ctx.Transaction.GetHttpRequest()!.HttpContext.RequestServices.GetRequiredService<IOpenIddictTokenManager>();
        var t = await manager.FindByReferenceIdAsync(ctx.Request.RefreshToken);
        if (t != null && await manager.HasStatusAsync(t, Statuses.Redeemed))
        {
            var subject = await manager.GetSubjectAsync(t);
            var db = ctx.Transaction.GetHttpRequest()!.HttpContext.RequestServices.GetRequiredService<State>();
            await db.Grants.Where(g => g.Id == subject).ExecuteUpdateAsync(s => s.SetProperty(g => g.Active, false));
            db.Record("refresh_reuse", subject ?? "unknown"); await db.SaveChangesAsync();
            ctx.Reject(Errors.InvalidGrant);
        }
    }));
    o.UseReferenceAccessTokens(); o.UseReferenceRefreshTokens();
}).AddValidation(o => { o.UseLocalServer(); o.UseAspNetCore(); o.EnableTokenEntryValidation(); o.AddAudiences(config.Required("Resource")); });
builder.Services.AddSingleton<AuthorizationGate>();
builder.Services.AddScoped<Grants>(); builder.Services.AddScoped<Cimd>();
var rsa = RSA.Create(); rsa.ImportFromPem(File.ReadAllText(config.Required("AssertionPrivateKey")));
builder.Services.AddSingleton(new Assertions(rsa, config.Required("Issuer")));
builder.Services.AddAuthorization(); builder.Services.AddAntiforgery(o => { o.Cookie.Name = "__Host-csrf"; o.Cookie.SecurePolicy = CookieSecurePolicy.Always; });
var app = builder.Build();
await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<State>();
    if (provision)
    {
        await db.Database.EnsureCreatedAsync();
        await OwnerConsole.ProvisionAsync(scope.ServiceProvider, config);
        return;
    }
    // Startup cannot silently recreate lost authorization storage.
    if (!File.Exists(config.Required("StateFile")) || !await db.Database.CanConnectAsync()) throw new InvalidOperationException("Provision authorization storage offline before startup.");
    // A restored backup must be explicitly marked offline and all grants invalidated.
    if (File.Exists(config.Required("StateFile") + ".restored")) throw new InvalidOperationException("Restored state requires offline invalidation.");
}
InternalTls.SafeErrors(app);
app.Use(async (ctx, next) => {
    var peer = InternalTls.Peer(ctx);
    var path = ctx.Request.Path;
    var allowed = path == "/internal/consume" ? peer == "gateway" : path.StartsWithSegments("/internal") ? peer == "mcp" : peer == "ingress";
    if (!allowed) { ctx.Response.StatusCode = 403; return; }
    if (peer == "ingress") { ctx.Request.Host = new HostString(new Uri(config.Required("Issuer")).Host); }
    // HTTPS is always mTLS; ingress never supplies an internal identity via headers.
    await next(ctx);
    if (ctx.Response.StatusCode >= 400) SecurityEvent.Write("policy_denied");
});
app.UseAuthentication(); app.UseAuthorization();
app.Use(async (ctx, next) => {
    if (ctx.Request.Path == "/connect/token" || ctx.Request.Path.StartsWithSegments("/internal") || ctx.Request.Path.StartsWithSegments("/owner"))
    {
        var gate = ctx.RequestServices.GetRequiredService<AuthorizationGate>().Lock;
        await gate.WaitAsync(ctx.RequestAborted);
        try { await next(ctx); } finally { gate.Release(); }
    }
    else await next(ctx);
});
app.MapGet("/.well-known/oauth-protected-resource", () => Results.Json(new { resource = config.Required("Resource"), authorization_servers = new[] { config.Required("Issuer") }, scopes_supported = new[] { "etrade.read" } }));
app.MapGet("/.well-known/oauth-authorization-server", () => Results.Json(new {
    issuer = config.Required("Issuer"), authorization_endpoint = config.Required("Issuer").TrimEnd('/') + "/connect/authorize",
    token_endpoint = config.Required("Issuer").TrimEnd('/') + "/connect/token", response_types_supported = new[] { "code" },
    grant_types_supported = new[] { "authorization_code", "refresh_token" }, code_challenge_methods_supported = new[] { "S256" },
    scopes_supported = new[] { "etrade.read", "offline_access" }, token_endpoint_auth_methods_supported = new[] { "none" },
    client_id_metadata_document_supported = true
}));
app.MapPost("/internal/validate", async (HttpContext ctx, Grants grants) => {
    var result = await ctx.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
    var status = result.Principal == null ? null : await grants.ValidateAsync(result.Principal);
    return status == null ? Results.Unauthorized() : Results.Json(status);
});
app.MapPost("/internal/assertions", async (HttpContext ctx, Grants grants, State db, Assertions assertions) => {
    var request = await StrictJson.ReadAsync<AssertionRequest>(ctx.Request.Body, ctx.RequestAborted);
    RequestPolicy.Validate(request.Request);
    var result = await ctx.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
    var status = result.Principal == null ? null : await grants.ValidateAsync(result.Principal);
    if (status == null) return Results.Unauthorized();
    var token = assertions.Issue(status, request.Request); var claims = assertions.Verify(token);
    db.Nonces.Add(new Nonce { Id = claims.FindFirstValue("jti")!, GrantId = status.GrantId, OriginTokenId = status.TokenId,
        ExpiresAt = long.Parse(claims.FindFirstValue("exp")!) });
    await db.SaveChangesAsync();
    return Results.Json(new AssertionReply(token));
});
app.MapPost("/internal/consume", async (HttpContext ctx, Grants grants, Assertions assertions) => {
    if (ctx.Request.Headers.Authorization.Count != 0) return Results.BadRequest();
    var request = await StrictJson.ReadAsync<ConsumeRequest>(ctx.Request.Body, ctx.RequestAborted);
    return await grants.ConsumeAsync(assertions.Verify(request.Assertion)) ? Results.Ok() : Results.Unauthorized();
});
OAuthEndpoints.Map(app);
OwnerConsole.Map(app);
await app.RunAsync();

namespace OpenEtradeMcp.Authorization { public sealed class AuthorizationEntryPoint { } }
