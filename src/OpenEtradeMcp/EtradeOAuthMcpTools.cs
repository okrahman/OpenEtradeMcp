using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace OpenEtradeMcp;

public sealed class EtradeOAuthMcpTools(EtradeOAuth1AuthenticationHandler authentication)
{
    private static string Json(object result) => JsonSerializer.Serialize(result);
    private static string Error(Exception ex) => Json(new { success = false, error =
        ex is EtradeOperationException or OAuthProviderException ? ex.Message : "OAuth request failed. Check OAuth status and retry." });

        [Description("Start OAuth authorization and return the URL to visit.")]
    public async Task<string> StartOAuthAsync()
    {
        try { return Json(new { success = true, authorizationUrl = await authentication.StartAsync(),
            instructions = "Visit the authorization URL and provide the verification code to etrade_oauth_complete." }); }
        catch (Exception ex) { return Error(ex); }
    }

        [Description("Exchange the verification code for access credentials.")]
    public async Task<string> CompleteOAuthAsync([Description("Verification code from E*TRADE.")] string verifierCode)
    {
        try { await authentication.CompleteAsync(verifierCode); return Json(new { success = true,
            message = "Authentication successful! You can now use E*TRADE API tools.", expiresAt = authentication.Session.ExpiresAt }); }
        catch (Exception ex) { return Error(ex); }
    }

        [Description("Check authentication and recovery status.")]
    public string GetOAuthStatus() => Json(new { isAuthenticated = authentication.IsAuthenticated,
        hasPendingAuthorization = authentication.Session.HasPendingAuthorization,
        authorizationUrl = authentication.Session.AuthorizationUrl, expiresAt = authentication.Session.ExpiresAt,
        recoveryStatus = authentication.Session.RecoveryStatus });

        [Description("Renew inactive credentials. Midnight Eastern expiration still requires reauthorization.")]
    public async Task<string> RenewOAuthAsync()
    {
        try { await authentication.RenewAsync(); return Json(new { success = true, message = "Access token renewed successfully.",
            expiresAt = authentication.Session.ExpiresAt, recoveryStatus = authentication.Session.RecoveryStatus }); }
        catch (Exception ex) { return Error(ex); }
    }

        [Description("Revoke access credentials and delete local persistence.")]
    public async Task<string> RevokeOAuthAsync()
    {
        try { await authentication.RevokeAsync(); return Json(new { success = true, message = "Access token revoked. You are now logged out." }); }
        catch (Exception ex) { return Error(ex); }
    }
}

// Only deliberately sanitized messages may be surfaced by the OAuth tools.
public sealed class EtradeOperationException(string message) : InvalidOperationException(message);
