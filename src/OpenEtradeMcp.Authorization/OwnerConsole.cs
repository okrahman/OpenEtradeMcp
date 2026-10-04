using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenEtradeMcp.Contracts;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace OpenEtradeMcp.Authorization;

public static class OwnerConsole
{
    public static async Task ProvisionAsync(IServiceProvider services, IConfiguration config)
    {
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Unix owner provisioning is required.");
        var manager = services.GetRequiredService<UserManager<Owner>>();
        var subject = config.Required("OwnerSubject");
        if (await manager.Users.AnyAsync()) throw new InvalidOperationException("Owner already provisioned.");
        var owner = new Owner { UserName = "owner", GoogleSubject = subject, EmailConfirmed = true };
        if (!(await manager.CreateAsync(owner)).Succeeded) throw new InvalidOperationException("Owner provisioning failed.");
        await manager.ResetAuthenticatorKeyAsync(owner); await manager.SetTwoFactorEnabledAsync(owner, true);
        var recoveryPath = Path.Combine(Path.GetDirectoryName(config.Required("StateFile"))!, "owner-bootstrap.txt");
        await using var recoveryFile = new FileStream(recoveryPath, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite, Options = FileOptions.WriteThrough });
        var bootstrap = "TOTP secret: " + await manager.GetAuthenticatorKeyAsync(owner) + "\nRecovery codes: " +
            string.Join(" ", (await manager.GenerateNewTwoFactorRecoveryCodesAsync(owner, 10))!);
        await recoveryFile.WriteAsync(System.Text.Encoding.UTF8.GetBytes(bootstrap)); recoveryFile.Flush(true);
        Console.WriteLine("Owner provisioned. Transfer owner-bootstrap.txt offline over IAP, enroll TOTP, then delete that file. No recovery secrets were logged.");
    }
    public static bool Recent(HttpContext ctx, IConfiguration config) =>
        ctx.User.Identity?.IsAuthenticated == true && ctx.User.FindFirstValue("google_subject") == config.Required("OwnerSubject") &&
        long.TryParse(ctx.User.FindFirstValue("mfa_at"), out var at) && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - at is >= 0 and <= 300;
    private static string ReturnUrl(string? value) => value != null && value.StartsWith('/') && !value.StartsWith("//") && !value.Contains('\\') ? value : "/owner";
    private static string Form(HttpContext ctx, string content)
    {
        var tokens = ctx.RequestServices.GetRequiredService<IAntiforgery>().GetAndStoreTokens(ctx);
        return "<!doctype html><meta charset='utf-8'><title>E*TRADE owner</title><form method='post'><input type='hidden' name='__RequestVerificationToken' value='" + tokens.RequestToken + "'>" + content + "</form>";
    }
    public static void Map(WebApplication app)
    {
        app.MapGet("/owner/login", (HttpContext ctx) => Results.Challenge(new AuthenticationProperties {
            RedirectUri = "/owner/external?returnUrl=" + Uri.EscapeDataString(ReturnUrl(ctx.Request.Query["returnUrl"])) }, ["Google"]));
        app.MapGet("/owner/external", async (HttpContext ctx, UserManager<Owner> users, IConfiguration config) => {
            var external = await ctx.AuthenticateAsync(IdentityConstants.ExternalScheme);
            var subject = external.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!external.Succeeded || subject != config.Required("OwnerSubject") || !await users.Users.AnyAsync(o => o.GoogleSubject == subject)) return Results.Forbid();
            return Results.Redirect("/owner/mfa?returnUrl=" + Uri.EscapeDataString(ReturnUrl(ctx.Request.Query["returnUrl"])));
        });
        app.MapGet("/owner/mfa", (HttpContext ctx) => Results.Content(Form(ctx, "<h1>Owner verification</h1><label>TOTP or offline recovery code<input name='code' autocomplete='one-time-code'></label><button>Verify</button>"), "text/html"));
        app.MapPost("/owner/mfa", async (HttpContext ctx, UserManager<Owner> users, IConfiguration config) => {
            await ctx.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(ctx);
            var ext = await ctx.AuthenticateAsync(IdentityConstants.ExternalScheme);
            var subject = ext.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!ext.Succeeded || subject != config.Required("OwnerSubject")) return Results.Forbid();
            var owner = await users.Users.SingleAsync(o => o.GoogleSubject == subject);
            if (await users.IsLockedOutAsync(owner)) return Results.StatusCode(429);
            var form = await ctx.Request.ReadFormAsync(); var code = form["code"].ToString().Replace(" ", "");
            var verified = await users.VerifyTwoFactorTokenAsync(owner, TokenOptions.DefaultAuthenticatorProvider, code);
            if (!verified) verified = (await users.RedeemTwoFactorRecoveryCodeAsync(owner, code)).Succeeded;
            if (!verified) { await users.AccessFailedAsync(owner); return Results.Forbid(); }
            await users.ResetAccessFailedCountAsync(owner);
            var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, owner.Id));
            identity.AddClaim(new Claim("google_subject", subject!)); identity.AddClaim(new Claim("mfa_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
            await ctx.SignInAsync(IdentityConstants.ApplicationScheme, new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = false });
            return Results.Redirect(ReturnUrl(ctx.Request.Query["returnUrl"]));
        });
        var group = app.MapGroup("/owner").AddEndpointFilter(async (context, next) => {
            var ctx = context.HttpContext; var config = ctx.RequestServices.GetRequiredService<IConfiguration>();
            if (!Recent(ctx, config)) return Results.Unauthorized();
            if (ctx.Request.Method != "GET") await ctx.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(ctx);
            return await next(context);
        });
        group.MapGet("", async (HttpContext ctx, State db, IConfiguration config) => {
            using var gateway = InternalTls.Client(config, "gateway", "GatewayUrl");
            using var status = await gateway.GetAsync("/admin/status");
            var state = WebUtility.HtmlEncode(await status.Content.ReadAsStringAsync());
            var clients = await db.Clients.AsNoTracking().ToListAsync(); var grants = await db.Grants.AsNoTracking().ToListAsync();
            var body = "<h1>E*TRADE owner console</h1><p>Production authorization expiry and recovery state:</p><pre>" + state + "</pre>" +
                "<p>Each client connection must be isolated to one persistent agent.</p><pre>" +
                WebUtility.HtmlEncode(JsonSerializer.Serialize(new { clients, grants }, new JsonSerializerOptions { WriteIndented = true })) + "</pre>";
            body += "<h2>Register or reapprove a client</h2>" + Form(ctx,
                "<input name='clientId' placeholder='Unique client ID' required><input name='platformIdentity' placeholder='Platform identity' required>" +
                "<input name='redirectUris' placeholder='Exact HTTPS redirect URI(s), separated by spaces' required>" +
                "<input name='metadataUrl' placeholder='Approved CIMD URL (optional)'><label><input name='isolatedConnection' type='checkbox' required>Isolated connection</label>" +
                "<input type='hidden' name='authMethod' value='none'><button data-endpoint='/owner/clients'>Approve client</button>");
            body += "<h2>Approve an agent grant</h2>" + Form(ctx,
                "<input name='agentId' placeholder='Unique persistent agent ID' required><input name='clientId' placeholder='Approved client ID' required>" +
                "<label><input name='isolatedConnection' type='checkbox' required>Isolated connection</label><button data-endpoint='/owner/grants'>Approve agent</button>");
            body += "<h2>Revoke</h2>" + Form(ctx,
                "<input name='id' placeholder='Grant ID' required><button data-endpoint='/owner/grants/{id}/revoke'>Revoke grant</button>") + Form(ctx,
                "<input name='id' placeholder='Client ID' required><button data-endpoint='/owner/clients/{id}/revoke'>Revoke client</button>");
            body += "<h2>Production brokerage authorization</h2>" + Form(ctx,
                "<button data-endpoint='/owner/brokerage/start'>Start authorization</button>") + Form(ctx,
                "<input name='verifier' placeholder='E*TRADE verification code' required autocomplete='off'><button data-endpoint='/owner/brokerage/complete'>Complete authorization</button>") + Form(ctx,
                "<button data-endpoint='/owner/brokerage/revoke'>Revoke brokerage authorization</button>");
            body += "<h2>Approve credential replacement</h2>" + Form(ctx,
                "<input name='consumer-key' placeholder='Consumer key Secret Manager version' required><input name='consumer-secret' placeholder='Consumer secret version' required>" +
                "<input name='token-key' placeholder='Encryption key version' required><button data-endpoint='/owner/credentials/approve'>Approve host replacement</button>");
            body += "<pre id='result'></pre><script src='/owner/console.js'></script>";
            body += "<p><a href='/owner/audit'>Redacted audit history</a></p>";
            return Results.Content(body, "text/html");
        });
        group.MapPost("/clients", async (HttpContext ctx, State db, Cimd cimd, IOpenIddictApplicationManager manager) => {
            var input = await StrictJson.ReadAsync<ClientEnrollment>(ctx.Request.Body, ctx.RequestAborted);
            if (!input.IsolatedConnection || input.ClientId.Length is < 1 or > 256 || input.PlatformIdentity.Length is < 1 or > 256 || input.RedirectUris.Length is < 1 or > 10)
                return Results.BadRequest();
            var hash = "";
            if (input.MetadataUrl != null)
            {
                var document = await cimd.FetchAsync(input.MetadataUrl, ctx.RequestAborted);
                if (document.ClientId != input.ClientId || !document.RedirectUris.Order().SequenceEqual(input.RedirectUris.Order()) || document.AuthMethod != input.AuthMethod) return Results.BadRequest();
                hash = document.Hash;
            }
            if (input.AuthMethod != "none") return Results.BadRequest();
            foreach (var redirect in input.RedirectUris) Cimd.ExactHttps(redirect);
            if (input.RedirectUris.Distinct(StringComparer.Ordinal).Count() != input.RedirectUris.Length) return Results.BadRequest();
            var existing = await db.Clients.FindAsync(input.ClientId);
            // Updates revoke the old grant before new metadata is approved; re-enrollment never resurrects a grant.
            if (existing != null) await db.Grants.Where(g => g.ClientId == input.ClientId).ExecuteUpdateAsync(s => s.SetProperty(g => g.Active, false));
            var desc = new OpenIddictApplicationDescriptor { ClientId = input.ClientId, ClientType = ClientTypes.Public, ConsentType = ConsentTypes.Explicit };
            foreach (var redirect in input.RedirectUris) desc.RedirectUris.Add(new Uri(redirect));
            foreach (var permission in new[] { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token, Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken, Permissions.ResponseTypes.Code, Permissions.Prefixes.Scope + "etrade.read", Permissions.Prefixes.Resource + ctx.RequestServices.GetRequiredService<IConfiguration>().Required("Resource") }) desc.Permissions.Add(permission);
            desc.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            var application = await manager.FindByClientIdAsync(input.ClientId);
            if (application == null) await manager.CreateAsync(desc); else await manager.UpdateAsync(application, desc);
            existing ??= new ApprovedClient { Id = input.ClientId };
            if (db.Entry(existing).State == EntityState.Detached) db.Clients.Add(existing);
            existing.PlatformIdentity = input.PlatformIdentity; existing.Active = true; existing.RedirectsJson = JsonSerializer.Serialize(input.RedirectUris);
            existing.MetadataUrl = input.MetadataUrl; existing.MetadataHash = hash; existing.AuthMethod = input.AuthMethod;
            db.Record("client_approved", input.ClientId); await db.SaveChangesAsync(); return Results.Ok();
        });
        group.MapPost("/credentials/approve", async (HttpContext ctx, State db) => {
            var input = await StrictJson.ReadAsync<CredentialReplacement>(ctx.Request.Body, ctx.RequestAborted);
            var names = new[] { "consumer-key", "consumer-secret", "token-key" };
            if (!input.Versions.Keys.Order().SequenceEqual(names.Order()) || input.Versions.Values.Any(v => !long.TryParse(v, out var version) || version <= 0)) return Results.BadRequest();
            var approval = new MaintenanceApproval { VersionsJson = JsonSerializer.Serialize(input.Versions), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() };
            db.MaintenanceApprovals.Add(approval); db.Record("credential_replacement_approved", approval.Id); await db.SaveChangesAsync();
            return Results.Json(new { approval.Id, approval.ExpiresAt });
        });
        group.MapPost("/grants", async (HttpContext ctx, State db) => {
            var input = await StrictJson.ReadAsync<GrantEnrollment>(ctx.Request.Body, ctx.RequestAborted);
            if (!input.IsolatedConnection || input.AgentId.Length is < 1 or > 128 || !await db.Clients.AnyAsync(c => c.Id == input.ClientId && c.Active)) return Results.BadRequest();
            var existing = await db.Grants.SingleOrDefaultAsync(g => g.ClientId == input.ClientId || g.AgentId == input.AgentId);
            if (existing != null) return Results.Conflict(); // No reassignment or resurrection; use a fresh client/agent identity.
            var grant = new AgentGrant { AgentId = input.AgentId, ClientId = input.ClientId, Active = true, ExpiresAt = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds() };
            db.Grants.Add(grant); db.Record("agent_approved", grant.AgentId); await db.SaveChangesAsync(); return Results.Json(new { grant.Id });
        });
        group.MapPost("/grants/{id}/revoke", async (string id, State db) => {
            await db.Grants.Where(g => g.Id == id).ExecuteUpdateAsync(s => s.SetProperty(g => g.Active, false));
            db.Record("agent_revoked", id); await db.SaveChangesAsync(); return Results.Ok();
        });
        group.MapPost("/clients/{id}/revoke", async (string id, State db) => {
            await db.Clients.Where(c => c.Id == id).ExecuteUpdateAsync(s => s.SetProperty(c => c.Active, false));
            await db.Grants.Where(g => g.ClientId == id).ExecuteUpdateAsync(s => s.SetProperty(g => g.Active, false));
            db.Record("client_revoked", id); await db.SaveChangesAsync(); return Results.Ok();
        });
        group.MapGet("/console.js", () => Results.Content("""
            document.querySelectorAll('form').forEach(form => form.addEventListener('submit', async event => {
                const button = event.submitter;
                if (!button?.dataset.endpoint) return;
                event.preventDefault();
                const data = Object.fromEntries(new FormData(form));
                const csrf = data.__RequestVerificationToken;
                delete data.__RequestVerificationToken;
                if ('redirectUris' in data) data.redirectUris = data.redirectUris.trim().split(/\s+/);
                if ('metadataUrl' in data && !data.metadataUrl) data.metadataUrl = null;
                if (form.elements.isolatedConnection) data.isolatedConnection = form.elements.isolatedConnection.checked;
                const endpoint = button.dataset.endpoint.replace('{id}', encodeURIComponent(data.id || ''));
                delete data.id;
                const result = await fetch(endpoint, {method:'POST', credentials:'same-origin',
                    headers:{'Content-Type':'application/json','RequestVerificationToken':csrf}, body:JSON.stringify(endpoint === '/owner/credentials/approve' ? {versions:data} : data)});
                const text = await result.text();
                document.getElementById('result').textContent = result.status + ' ' + text;
                try {
                    const value = JSON.parse(text);
                    if (value.authorizationUrl) {
                        const url = new URL(value.authorizationUrl);
                        if (url.protocol === 'https:' && url.hostname === 'us.etrade.com') {
                            const link = document.createElement('a'); link.href = url.href;
                            link.rel = 'noopener noreferrer'; link.textContent = 'Authorize with E*TRADE';
                            document.getElementById('result').appendChild(link);
                        }
                    }
                } catch {}
            }));
            """, "text/javascript"));
        group.MapGet("/audit", async (State db) => Results.Json(await db.Audits.AsNoTracking().OrderByDescending(a => a.Id).Take(100).ToArrayAsync()));
        group.MapPost("/brokerage/{action}", async (string action, HttpContext ctx, IConfiguration config, State db) => {
            if (action is not ("start" or "complete" or "revoke")) return Results.NotFound();
            var input = action == "complete" ? await StrictJson.ReadAsync<CompleteAuthorization>(ctx.Request.Body, ctx.RequestAborted) : new CompleteAuthorization("");
            using var gateway = InternalTls.Client(config, "gateway", "GatewayUrl");
            using var response = await gateway.PostAsJsonAsync("/admin/" + action, input, ctx.RequestAborted);
            db.Record("brokerage_" + action, "owner"); await db.SaveChangesAsync();
            return Results.Content(await response.Content.ReadAsStringAsync(ctx.RequestAborted), "application/json", statusCode: (int)response.StatusCode);
        });
    }
}
public sealed record GrantEnrollment(string AgentId, string ClientId, bool IsolatedConnection);
public sealed record CompleteAuthorization(string Verifier);

public sealed record CredentialReplacement(Dictionary<string, string> Versions);
