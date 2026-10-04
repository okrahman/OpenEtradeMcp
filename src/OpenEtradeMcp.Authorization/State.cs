using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenEtradeMcp.Contracts;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace OpenEtradeMcp.Authorization;

public sealed class Owner : IdentityUser { public string GoogleSubject { get; set; } = ""; }
public sealed class ApprovedClient
{
    public string Id { get; set; } = "";
    public string PlatformIdentity { get; set; } = "";
    public bool Active { get; set; }
    public string RedirectsJson { get; set; } = "[]";
    public string MetadataHash { get; set; } = "";
    public string? MetadataUrl { get; set; }
    public string AuthMethod { get; set; } = "none";
}
public sealed class AgentGrant
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string AgentId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public bool Active { get; set; }
    public long ExpiresAt { get; set; }
    public long LastUse { get; set; }
}
public sealed class Nonce
{
    public string Id { get; set; } = "";
    public string OriginTokenId { get; set; } = "";
    public string GrantId { get; set; } = "";
    public long ExpiresAt { get; set; }
    public bool Consumed { get; set; }
}
public sealed class Audit
{
    public long Id { get; set; }
    public long At { get; set; }
    public string Action { get; set; } = "";
    public string Subject { get; set; } = "";
}
public sealed class State(DbContextOptions<State> options) : IdentityDbContext<Owner>(options)
{
    public DbSet<ApprovedClient> Clients => Set<ApprovedClient>();
    public DbSet<AgentGrant> Grants => Set<AgentGrant>();
    public DbSet<Nonce> Nonces => Set<Nonce>();
    public DbSet<Audit> Audits => Set<Audit>();
    public DbSet<MaintenanceApproval> MaintenanceApprovals => Set<MaintenanceApproval>();
    protected override void OnModelCreating(ModelBuilder model)
    {
        base.OnModelCreating(model);
        model.UseOpenIddict();
        // Every persistent connection has one client credential and one agent.
        model.Entity<AgentGrant>().HasIndex(g => g.ClientId).IsUnique();
        model.Entity<AgentGrant>().HasIndex(g => g.AgentId).IsUnique();
        model.Entity<Owner>().HasIndex(o => o.GoogleSubject).IsUnique();
    }
    public void Record(string action, string subject)
    {
        Audits.Add(new Audit { At = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Action = action, Subject = subject });
    }
}
// Serializes checks, issuance, consumption, revocation and refresh redemption on this single VM.
// Persistent SQLite nonce rows enforce replay protection across service restarts.
public sealed class AuthorizationGate { public readonly SemaphoreSlim Lock = new(1, 1); }
public sealed class Grants(State db, IOpenIddictTokenManager tokens, IOpenIddictApplicationManager applications, IConfiguration config)
{
    public async Task<TokenStatus?> ValidateAsync(ClaimsPrincipal p)
    {
        if (p.Identity?.IsAuthenticated != true || !p.HasScope("etrade.read") ||
            !p.GetAudiences().Contains(config.Required("Resource"), StringComparer.Ordinal)) return null;
        var tokenId = p.GetTokenId();
        if (tokenId == null) return null;
        var token = await tokens.FindByIdAsync(tokenId);
        if (token == null || !await tokens.HasStatusAsync(token, Statuses.Valid) ||
            await tokens.GetTypeAsync(token) != TokenTypeIdentifiers.AccessToken ||
            await tokens.GetExpirationDateAsync(token) is not { } exp || exp <= DateTimeOffset.UtcNow) return null;
        var id = p.FindFirstValue("grant"); var agent = p.FindFirstValue("agent"); var client = p.FindFirstValue("client");
        if (id == null || agent == null || client == null) return null;
        var appId = await tokens.GetApplicationIdAsync(token);
        var application = appId == null ? null : await applications.FindByIdAsync(appId);
        if (application == null || await applications.GetClientIdAsync(application) != client) return null;
        return await ActiveAsync(id, agent, client) ? new(agent, id, client, tokenId) : null;
    }
    public async Task<bool> ActiveAsync(string id, string agent, string client)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return await db.Clients.AnyAsync(c => c.Id == client && c.Active) &&
            await db.Grants.AnyAsync(g => g.Id == id && g.Active && g.AgentId == agent && g.ClientId == client && g.ExpiresAt > now);
    }
    public async Task<bool> ConsumeAsync(ClaimsPrincipal p)
    {
        var grant = p.FindFirstValue("grant")!; var origin = p.FindFirstValue("origin")!;
        if (!await ActiveAsync(grant, p.FindFirstValue("agent")!, p.FindFirstValue("client")!)) return false;
        var token = await tokens.FindByIdAsync(origin);
        if (token == null || !await tokens.HasStatusAsync(token, Statuses.Valid) || await tokens.GetTypeAsync(token) != TokenTypeIdentifiers.AccessToken ||
            await tokens.GetExpirationDateAsync(token) is not { } exp || exp <= DateTimeOffset.UtcNow) return false;
        var nonce = p.FindFirstValue("jti")!; var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var changed = await db.Nonces.Where(n => n.Id == nonce && n.GrantId == grant && n.OriginTokenId == origin && !n.Consumed && n.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(n => n.Consumed, true));
        if (changed != 1) { await transaction.RollbackAsync(); return false; }
        await db.Grants.Where(g => g.Id == grant).ExecuteUpdateAsync(set => set.SetProperty(g => g.LastUse, now));
        db.Record("read_authorized", p.FindFirstValue("agent")!);
        await db.SaveChangesAsync(); await transaction.CommitAsync(); return true;
    }
}

public sealed class MaintenanceApproval
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Action { get; set; } = "credential_replacement";
    public string VersionsJson { get; set; } = "{}";
    public long ExpiresAt { get; set; }
    public bool Consumed { get; set; }
}
