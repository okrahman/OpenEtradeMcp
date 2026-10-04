using System.Net.Http.Headers;
using System.Text.Json;
using System.Web;
using OpenApiMcpNet;

namespace OpenEtradeMcp;

public sealed class EtradeOAuthSession
{
    internal DateTimeOffset? PendingUntil { get; set; }
    internal string? RequestToken { get; set; }
    internal string? RequestTokenSecret { get; set; }
    public string? AuthorizationUrl { get; internal set; }
    public bool HasPendingAuthorization => RequestToken != null;
    public DateTimeOffset? ExpiresAt { get; internal set; }
    public string RecoveryStatus { get; internal set; } = "unauthenticated";
    public bool IsAuthenticated => RecoveryStatus == "ready" && ExpiresAt > Clock.GetUtcNow();
    internal TimeProvider Clock { get; set; } = TimeProvider.System;
}

// One synchronized credential holder supplies both status and request signing.
public sealed class EtradeOAuth1AuthenticationHandler : IAuthenticationHandler
{
    private readonly SignatureSupport signer;
    private readonly HttpClient client;
    private readonly ETradeConfig config;
    private readonly ITokenStore store;
    private readonly TimeProvider clock;
    private readonly SemaphoreSlim gate = new(1, 1);
    private OAuthCredentials? credentials;
    private DateTimeOffset lastActivity;
    public EtradeOAuthSession Session { get; }
    public bool IsAuthenticated => Session.IsAuthenticated;

    public EtradeOAuth1AuthenticationHandler(HttpClient client, ETradeConfig config, ITokenStore store,
        EtradeOAuthSession? session = null, TimeProvider? clock = null)
    {
        signer = new SignatureSupport(client, config);
        this.client = client;
        this.config = config;
        this.store = store;
        this.clock = clock ?? TimeProvider.System;
        Session = session ?? new();
        Session.Clock = this.clock;
    }

    private void Set(OAuthCredentials? value, string status)
    {
        credentials = value;
        Session.ExpiresAt = value?.ExpiresAt;
        Session.RecoveryStatus = status;
    }

    public static DateTimeOffset MidnightEastern(DateTimeOffset issued)
    {
        var eastern = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
        var nextDate = TimeZoneInfo.ConvertTime(issued, eastern).Date.AddDays(1);
        return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(nextDate, eastern), TimeSpan.Zero);
    }

    public async Task InitializeAsync()
    {
        await gate.WaitAsync();
        try
        {
            Set(await store.LoadAsync(), "recovering");
            if (credentials == null) { Set(null, "unauthenticated"); return; }
            if (await ExpireAsync()) return;
            try { await RenewCoreAsync(); }
            catch (OAuthProviderException ex) when (ex.InvalidToken) { /* Definitive invalidation already cleared and deleted. */ }
            catch (OAuthProviderException ex) when (!ex.InvalidToken) { Session.RecoveryStatus = "recovery_required"; }
            catch (HttpRequestException) { Session.RecoveryStatus = "recovery_required"; }
            catch (TaskCanceledException) { Session.RecoveryStatus = "recovery_required"; }
        }
        finally { gate.Release(); }
    }

    private async Task<bool> ExpireAsync()
    {
        if (credentials == null || clock.GetUtcNow() < credentials.ExpiresAt) return false;
        Set(null, "expired");
        await store.DeleteAsync();
        return true;
    }

    public string GetAuthorizationUrl(string token) =>
        $"https://us.etrade.com/e/t/etws/authorize?key={Uri.EscapeDataString(config.ConsumerKey)}&token={Uri.EscapeDataString(token)}";

    public async Task<string> StartAsync()
    {
        await gate.WaitAsync();
        try
        {
            if (Session.RequestToken != null && Session.PendingUntil > clock.GetUtcNow())
                throw new EtradeOperationException("An owner authorization flow is already pending.");
            Session.RequestToken = Session.RequestTokenSecret = Session.AuthorizationUrl = null;
            var result = await OAuthAsync("request_token", null, "", new() { ["oauth_callback"] = config.CallbackUrl });
            var pair = ParseSafe(result);
            Session.PendingUntil = clock.GetUtcNow().AddMinutes(10);
            Session.RequestToken = pair.Token;
            Session.RequestTokenSecret = pair.Secret;
            return Session.AuthorizationUrl = GetAuthorizationUrl(pair.Token);
        }
        finally { gate.Release(); }
    }

    private static (string Token, string Secret) ParseSafe(string result)
    {
        var values = HttpUtility.ParseQueryString(result);
        if (string.IsNullOrEmpty(values["oauth_token"]) || string.IsNullOrEmpty(values["oauth_token_secret"]))
            throw new EtradeOperationException("Provider returned an invalid OAuth response.");
        return (values["oauth_token"]!, values["oauth_token_secret"]!);
    }

    public async Task CompleteAsync(string verifier)
    {
        await gate.WaitAsync();
        try
        {
            if (Session.RequestToken == null || Session.PendingUntil <= clock.GetUtcNow())
            {
                Session.RequestToken = Session.RequestTokenSecret = Session.AuthorizationUrl = null;
                throw new EtradeOperationException("Owner authorization flow is absent or expired.");
            }
            if (string.IsNullOrWhiteSpace(verifier)) throw new EtradeOperationException("Verifier code is required.");
            var issued = clock.GetUtcNow();
            var pair = ParseSafe(await OAuthAsync("access_token", Session.RequestToken, Session.RequestTokenSecret!,
                new() { ["oauth_verifier"] = verifier.Trim() }));
            var value = new OAuthCredentials(pair.Token, pair.Secret, issued, issued, MidnightEastern(issued));
            if (clock.GetUtcNow() >= value.ExpiresAt) throw new EtradeOperationException("Authorization expired. Reauthorize.");
            await store.SaveAsync(value);
            Set(value, "ready");
            lastActivity = clock.GetUtcNow();
            Session.RequestToken = Session.RequestTokenSecret = Session.AuthorizationUrl = null;
        }
        finally { gate.Release(); }
    }

    private async Task RenewCoreAsync()
    {
        if (await ExpireAsync() || credentials == null) throw new EtradeOperationException("Owner reauthorization required.");
        Session.RecoveryStatus = "recovering";
        try
        {
            await OAuthAsync("renew_access_token", credentials.Token, credentials.Secret);
            if (await ExpireAsync()) throw new EtradeOperationException("Authorization expired. Reauthorize.");
            var renewed = credentials with { RenewedAt = clock.GetUtcNow() };
            await store.SaveAsync(renewed);
            Set(renewed, "ready");
            lastActivity = clock.GetUtcNow();
        }
        catch (OAuthProviderException ex) when (ex.InvalidToken)
        {
            Set(null, "invalidated");
            await store.DeleteAsync();
            throw;
        }
        catch { if (credentials != null) Session.RecoveryStatus = "recovery_required"; throw; }
    }

    public async Task RenewAsync()
    {
        await gate.WaitAsync();
        try { await RenewCoreAsync(); }
        finally { gate.Release(); }
    }

    public async Task RevokeAsync()
    {
        await gate.WaitAsync();
        try
        {
            if (credentials == null) throw new EtradeOperationException("Not authenticated. Nothing to revoke.");
            try { await OAuthAsync("revoke_access_token", credentials.Token, credentials.Secret); }
            catch (OAuthProviderException ex) when (ex.InvalidToken)
            {
                Set(null, "invalidated");
                await store.DeleteAsync();
                throw;
            }
            Set(null, "unauthenticated");
            Session.RequestToken = Session.RequestTokenSecret = Session.AuthorizationUrl = null;
            await store.DeleteAsync();
        }
        finally { gate.Release(); }
    }

    public Task AuthenticateAsync() => RenewAsync();
    public void AuthenticateRequest(HttpRequestMessage request, IEnumerable<KeyValuePair<string, string>> queryParameters,
        IEnumerable<KeyValuePair<string, JsonElement>> bodyParameters) { /* Signed after recovery in outbound guard. */ }

    public async Task<HttpResponseMessage> SendBusinessAsync(HttpRequestMessage request, Func<Task<HttpResponseMessage>> send)
    {
        await gate.WaitAsync();
        try
        {
            if (await ExpireAsync() || credentials == null) throw new EtradeOperationException("Owner reauthorization required.");
            if (!Session.IsAuthenticated || clock.GetUtcNow() - lastActivity >= TimeSpan.FromMinutes(110)) await RenewCoreAsync();
            var parameters = signer.Parameters(credentials!.Token);
            parameters["oauth_timestamp"] = clock.GetUtcNow().ToUnixTimeSeconds().ToString();
            var all = new SortedDictionary<string, string>(parameters);
            var query = HttpUtility.ParseQueryString(request.RequestUri!.Query);
            foreach (string name in query.AllKeys.Where(k => k != null)!) all[name] = query[name]!;
            parameters["oauth_signature"] = signer.Sign(request.Method.Method, request.RequestUri, all, credentials.Secret);
            request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", signer.Header(parameters));
            var response = await send();
            if (response.IsSuccessStatusCode) lastActivity = clock.GetUtcNow();
            else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                try
                {
                    var body = await response.Content.ReadAsStringAsync();
                    if (IsInvalidToken(body)) { Set(null, "invalidated"); await store.DeleteAsync(); }
                    else Session.RecoveryStatus = "recovery_required";
                }
                finally { response.Dispose(); }
                throw new EtradeOperationException("Owner reauthorization required.");
            }
            return response;
        }
        finally { gate.Release(); }
    }

    private static bool IsInvalidToken(string body)
    {
        var problem = HttpUtility.ParseQueryString(body)["oauth_problem"];
        return problem is "token_expired" or "token_rejected" or "token_revoked";
    }

    private async Task<string> OAuthAsync(string endpoint, string? token, string secret, Dictionary<string, string>? extra = null)
    {
        var method = HttpMethod.Get;
        var uri = new Uri($"https://api.etrade.com/oauth/{endpoint}");
        var parameters = signer.Parameters(token);
        parameters["oauth_timestamp"] = clock.GetUtcNow().ToUnixTimeSeconds().ToString();
        if (extra != null) foreach (var pair in extra) parameters[pair.Key] = pair.Value;
        parameters["oauth_signature"] = signer.Sign(method.Method, uri, parameters, secret);
        using var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", signer.Header(parameters));
        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) throw new OAuthProviderException(IsInvalidToken(body));
        return body;
    }
    // Keep the dependency's cached authentication state unreachable. Only signing helpers are exposed.
    private sealed class SignatureSupport(HttpClient client, ETradeConfig config)
        : OAuth1AuthenticationHandler(client, "https://api.etrade.com/oauth/request_token",
            "https://api.etrade.com/oauth/access_token", config.ConsumerKey, config.ConsumerSecret, config.SignatureMethod)
    {
        public SortedDictionary<string, string> Parameters(string? token) => GetOAuthParameters(token);
        public string Sign(string method, Uri uri, SortedDictionary<string, string> parameters, string secret) =>
            GenerateSignature(method, uri, parameters, secret);
        public string Header(IDictionary<string, string> parameters) => BuildAuthorizationHeader(parameters);
    }

}

public sealed class OAuthProviderException(bool invalidToken) : Exception("OAuth provider request failed. Check OAuth status and retry.")
{
    public bool InvalidToken { get; } = invalidToken;
}
