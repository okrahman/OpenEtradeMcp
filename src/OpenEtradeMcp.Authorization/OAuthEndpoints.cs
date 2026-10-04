using Microsoft.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using OpenEtradeMcp.Contracts;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace OpenEtradeMcp.Authorization;

public static class OAuthEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapMethods("/connect/authorize", ["GET", "POST"], async (HttpContext ctx, State db, IConfiguration config, Cimd cimd) => {
            var req = ctx.GetOpenIddictServerRequest()!;
            if (!req.IsAuthorizationCodeFlow() || req.CodeChallengeMethod != "S256" || string.IsNullOrEmpty(req.CodeChallenge) ||
                req.GetResources().Length != 1 || req.GetResources()[0] != config.Required("Resource") ||
                req.GetScopes().Any(s => s is not ("etrade.read" or "offline_access")) || !req.GetScopes().Contains("etrade.read"))
                return Results.BadRequest(new { error = "invalid_request" });
            var client = await db.Clients.SingleOrDefaultAsync(c => c.Id == req.ClientId && c.Active);
            var grant = await db.Grants.SingleOrDefaultAsync(g => g.ClientId == req.ClientId && g.Active);
            if (client == null || grant == null || grant.ExpiresAt <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return Results.Forbid();
            var redirects = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.RedirectsJson)!;
            if (!redirects.Contains(req.RedirectUri, StringComparer.Ordinal)) return Results.BadRequest(new { error = "invalid_redirect_uri" });
            if (client.MetadataUrl != null)
            {
                var doc = await cimd.FetchAsync(client.MetadataUrl, ctx.RequestAborted);
                if (doc.Hash != client.MetadataHash) return Results.BadRequest(new { error = "client_reapproval_required" });
            }
            // The owner must authenticate and confirm each isolated agent connection; platform identity is insufficient.
            if (!OwnerConsole.Recent(ctx, config)) return Results.Redirect("/owner/login?returnUrl=" + Uri.EscapeDataString(ctx.Request.Path + ctx.Request.QueryString));
            if (ctx.Request.Method == "GET")
            {
                var token = ctx.RequestServices.GetRequiredService<Microsoft.AspNetCore.Antiforgery.IAntiforgery>().GetAndStoreTokens(ctx);
                var hidden = string.Concat(ctx.Request.Query.Select(p =>
                    "<input type='hidden' name='" + System.Net.WebUtility.HtmlEncode(p.Key) + "' value='" + System.Net.WebUtility.HtmlEncode(p.Value.ToString()) + "'>"));
                var body = "<h1>Approve agent connection</h1><p>Agent: " + System.Net.WebUtility.HtmlEncode(grant.AgentId) + "</p>" +
                    "<p>Read account and market data for this isolated connection.</p><form method='post'>" +
                    hidden + "<input type='hidden' name='__RequestVerificationToken' value='" + token.RequestToken + "'><button>Approve</button></form>";
                return Results.Content(body, "text/html");
            }
            await ctx.RequestServices.GetRequiredService<Microsoft.AspNetCore.Antiforgery.IAntiforgery>().ValidateRequestAsync(ctx);
            var identity = new ClaimsIdentity("Bearer", Claims.Name, Claims.Role);
            identity.SetClaim(Claims.Subject, grant.Id); identity.SetClaim("grant", grant.Id); identity.SetClaim("agent", grant.AgentId); identity.SetClaim("client", grant.ClientId);
            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(req.GetScopes()); principal.SetResources(config.Required("Resource"));
            principal.SetPresenters(grant.ClientId);
            principal.SetRefreshTokenLifetime(TimeSpan.FromSeconds(grant.ExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
            principal.SetDestinations(_ => [Destinations.AccessToken]);
            db.Record("connection_approved", grant.AgentId); await db.SaveChangesAsync();
            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });
        app.MapPost("/connect/token", async (HttpContext ctx, State db, IConfiguration config) => {
            var req = ctx.GetOpenIddictServerRequest()!;
            if (!req.IsAuthorizationCodeGrantType() && !req.IsRefreshTokenGrantType()) return Results.BadRequest(new { error = "unsupported_grant_type" });
            var result = await ctx.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var p = result.Principal;
            if (p == null || !p.HasScope("etrade.read") || !p.GetResources().Contains(config.Required("Resource")))
                return Results.BadRequest(new { error = "invalid_grant" });
            var grant = await db.Grants.SingleOrDefaultAsync(g => g.Id == p.FindFirstValue("grant") && g.Active && g.ClientId == req.ClientId);
            if (grant == null || !await db.Clients.AnyAsync(c => c.Id == grant.ClientId && c.Active) || grant.ExpiresAt <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                return Results.BadRequest(new { error = "invalid_grant" });
            p.SetRefreshTokenLifetime(TimeSpan.FromSeconds(grant.ExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
            p.SetAccessTokenLifetime(TimeSpan.FromMinutes(5));
            return Results.SignIn(p, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });
    }
}
