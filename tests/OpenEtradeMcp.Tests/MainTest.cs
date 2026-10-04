using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;
using OpenApiMcpNet;

namespace OpenEtradeMcp.Tests;

public sealed class SecurityTests
{
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Provider : HttpMessageHandler
    {
        public int Calls;
        public string? Authorization;
        public HttpStatusCode Status = HttpStatusCode.OK;
        public string Body = "oauth_token=access&oauth_token_secret=secret";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            Authorization = request.Headers.Authorization?.ToString();
            return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Body) });
        }
    }
    private sealed class StoreFixture : IDisposable
    {
        public string Root = Path.Combine(OperatingSystem.IsMacOS() ? "/private/tmp" : Path.GetTempPath(), "etrade-test-" + Guid.NewGuid());
        public ETradeConfig Config;
        public StoreFixture()
        {
            if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var key = Path.Combine(Root, "key");
            File.WriteAllBytes(key, RandomNumberGenerator.GetBytes(32));
            File.SetUnixFileMode(key, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Config = new() { ConsumerKey = "consumer", ConsumerSecret = "consumer-secret",
                TokenDirectory = Path.Combine(Root, "tokens"), TokenKeyFile = key };
        }
        public void Dispose() => Directory.Delete(Root, true);
    }
    private static readonly DateTimeOffset Noon = DateTimeOffset.Parse("2026-09-26T16:00:00Z");
    private static OAuthCredentials Credentials => new("access", "secret", Noon, Noon, EtradeOAuth1AuthenticationHandler.MidnightEastern(Noon));

    [Fact]
    public void Discovery_RegistersExactlyTenReads()
    {
        var spec = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "etrade-api.yaml"));
        var document = ReadOnlyPolicy.Filter(spec);
        Assert.Equal(ReadOnlyPolicy.Operations.Keys.Order(), document.Paths.Values.SelectMany(p => p.Operations.Values).Select(o => o.OperationId).Order());
        Assert.DoesNotContain("operationId: placeOrder", spec);
        Assert.DoesNotContain("operationId: cancelOrder", spec);
        Assert.DoesNotContain("operationId: placeChangeOrder", spec);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(new HttpClient());
        services.AddSingleton<IAuthenticationHandler, NoOpAuthenticationHandler>();
        services.AddMcpServer().WithToolsFromOpenApi(document, ETradeConfig.ProductionBaseUrl);
        using var provider = services.BuildServiceProvider();
        var tools = provider.GetServices<McpServerTool>().ToArray();
        Assert.Equal(10, tools.Length);
        Assert.DoesNotContain(tools, t => new[] { "placeOrder", "cancelOrder", "placeChangeOrder" }.Contains(t.ProtocolTool.Name));
        Assert.Equal(0, typeof(EtradeOAuthMcpTools).GetMethods().Count(m => m.GetCustomAttributes(typeof(McpServerToolAttribute), false).Length > 0));
    }

    [Theory]
    [InlineData("POST", "/v1/accounts/abc/orders/place")]
    [InlineData("PUT", "/v1/accounts/abc/orders/cancel")]
    [InlineData("PUT", "/v1/accounts/abc/orders/1/change/place")]
    [InlineData("DELETE", "/v1/accounts/abc/orders")]
    [InlineData("POST", "/oauth/access_token")]
    [InlineData("POST", "/oauth/request_token")]
    [InlineData("GET", "/v1/accounts/a%2Fb/balance")]
    public async Task Guard_BlocksBeforeTransmission(string method, string path)
    {
        var network = new Provider();
        using var client = new HttpClient(new ReadOnlyGuard(new(), false) { InnerHandler = network });
        await Assert.ThrowsAsync<EtradeOperationException>(() => client.SendAsync(new(new HttpMethod(method), "https://api.etrade.com" + path)));
        Assert.Equal(0, network.Calls);
    }

    [Fact]
    public void Guard_AllowsEveryReadAndDedicatedOAuth()
    {
        foreach (var route in ReadOnlyPolicy.Operations.Values)
        {
            var path = System.Text.RegularExpressions.Regex.Replace(route.Path, "\\{[^}]+\\}", "abc");
            ReadOnlyPolicy.Validate(new(new HttpMethod(route.Method), "https://api.etrade.com/v1" + path), new(), false);
        }
        ReadOnlyPolicy.Validate(new(HttpMethod.Get, "https://api.etrade.com/oauth/request_token"), new(), true);
        Assert.Throws<EtradeOperationException>(() => ReadOnlyPolicy.Validate(new(HttpMethod.Get, "https://evil.example/v1/accounts/list"), new(), false));
    }

    [Fact]
    public async Task Encryption_RoundtripFreshNonceAndInterruptedWrite()
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = new StoreFixture();
        using var store = new EncryptedFileTokenStore(fixture.Config);
        await store.SaveAsync(Credentials);
        var path = Path.Combine(fixture.Config.TokenDirectory, "credentials.json");
        var first = await File.ReadAllTextAsync(path);
        Assert.DoesNotContain("secret", first);
        Assert.Equal(Credentials, await store.LoadAsync());
        await store.SaveAsync(Credentials);
        Assert.NotEqual(first, await File.ReadAllTextAsync(path));
        File.WriteAllText(path + ".interrupted.tmp", "partial");
        Assert.Equal(Credentials, await store.LoadAsync());
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        await store.DeleteAsync();
        Assert.Null(await store.LoadAsync());
    }

    [Fact]
    public void StoreLock_ExcludesCompetingProcessAndReleasesOnClose()
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = new StoreFixture();
        var store = new EncryptedFileTokenStore(fixture.Config);
        int Probe()
        {
            var start = new System.Diagnostics.ProcessStartInfo("python3") { RedirectStandardError = true };
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("import fcntl,sys; f=open(sys.argv[1], 'r+'); fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)");
            start.ArgumentList.Add(Path.Combine(fixture.Config.TokenDirectory, "store.lock"));
            using var process = System.Diagnostics.Process.Start(start)!;
            process.WaitForExit();
            return process.ExitCode;
        }
        Assert.NotEqual(0, Probe());
        Assert.Throws<EtradeOperationException>(() => new EncryptedFileTokenStore(fixture.Config));
        store.Dispose();
        Assert.Equal(0, Probe());
        using var fresh = new EncryptedFileTokenStore(fixture.Config);
    }

    [Fact]
    public void Configuration_RejectsMissingKeyRelativePathsInsecureKeyAndSymlinks()
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = new StoreFixture();
        var config = fixture.Config;
        var directory = config.TokenDirectory;
        config.TokenDirectory = "relative";
        Assert.Throws<EtradeOperationException>(() => new EncryptedFileTokenStore(config));
        config.TokenDirectory = directory;
        File.SetUnixFileMode(config.TokenKeyFile, UnixFileMode.UserRead | UnixFileMode.OtherRead);
        Assert.Throws<EtradeOperationException>(() => new EncryptedFileTokenStore(config));
        File.SetUnixFileMode(config.TokenKeyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Directory.CreateSymbolicLink(directory, fixture.Root);
        Assert.Throws<EtradeOperationException>(() => new EncryptedFileTokenStore(config));
        Directory.Delete(directory);
        File.Delete(config.TokenKeyFile);
        Assert.Throws<EtradeOperationException>(() => new EncryptedFileTokenStore(config));
    }

    [Theory]
    [InlineData("key")]
        [InlineData("consumer")]
    [InlineData("tamper")]
    [InlineData("version")]
    [InlineData("permissions")]
    public async Task Storage_RejectsUntrustedState(string change)
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = new StoreFixture();
        using (var store = new EncryptedFileTokenStore(fixture.Config)) await store.SaveAsync(Credentials);
        var path = Path.Combine(fixture.Config.TokenDirectory, "credentials.json");
        switch (change)
        {
            case "key": File.WriteAllBytes(fixture.Config.TokenKeyFile, RandomNumberGenerator.GetBytes(32)); break;
                        case "consumer": fixture.Config.ConsumerKey = "different"; break;
            case "tamper": var json = JsonNodeFor(path); json["Tag"] = Convert.ToBase64String(new byte[16]); File.WriteAllText(path, json.ToJsonString()); break;
            case "version": File.WriteAllText(path, File.ReadAllText(path).Replace("\"Version\":1", "\"Version\":9")); break;
            case "permissions": File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead); break;
        }
        using var restored = new EncryptedFileTokenStore(fixture.Config);
        var error = await Assert.ThrowsAsync<EtradeOperationException>(() => restored.LoadAsync());
        Assert.DoesNotContain("secret", error.Message);
    }
    private static System.Text.Json.Nodes.JsonObject JsonNodeFor(string path) => System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path))!.AsObject();

    [Fact]
    public async Task Authentication_FreshInstanceRenewsAndSigns()
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = new StoreFixture();
        var clock = new Clock(Noon);
        using (var store = new EncryptedFileTokenStore(fixture.Config))
        {
            using var client = new HttpClient(new Provider());
            var auth = new EtradeOAuth1AuthenticationHandler(client, fixture.Config, store, clock: clock);
            await auth.InitializeAsync();
            Assert.False(auth.IsAuthenticated);
            await auth.StartAsync();
            await auth.CompleteAsync("verifier");
            Assert.True(auth.IsAuthenticated);
        }
        using var restoredStore = new EncryptedFileTokenStore(fixture.Config);
        var oauth = new Provider();
        using var oauthClient = new HttpClient(oauth);
        var restored = new EtradeOAuth1AuthenticationHandler(oauthClient, fixture.Config, restoredStore, clock: clock);
        await restored.InitializeAsync();
        Assert.True(restored.IsAuthenticated);
        Assert.Equal(1, oauth.Calls);
        var network = new Provider { Body = "{}" };
        using var business = new HttpClient(new ReadOnlyGuard(fixture.Config, false, restored) { InnerHandler = network });
        await business.GetAsync("https://api.etrade.com/v1/accounts/list");
        Assert.Contains("oauth_token=\"access\"", network.Authorization);
        Assert.Contains("oauth_signature=", network.Authorization);
        clock.Now = Noon.AddMinutes(111);
        await business.GetAsync("https://api.etrade.com/v1/accounts/list");
        Assert.Equal(2, oauth.Calls);
        Assert.Equal(clock.Now, (await restoredStore.LoadAsync())!.RenewedAt);
        Assert.Equal(Credentials.ExpiresAt, (await restoredStore.LoadAsync())!.ExpiresAt);
    }

    [Fact]
    public async Task TransientRestoreFailure_RetriesBeforeBusinessAndInvalidationClears()
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = new StoreFixture();
        using var store = new EncryptedFileTokenStore(fixture.Config);
        await store.SaveAsync(Credentials);
        var provider = new Provider { Status = HttpStatusCode.ServiceUnavailable, Body = "secret raw response" };
        using var client = new HttpClient(provider);
        var auth = new EtradeOAuth1AuthenticationHandler(client, fixture.Config, store, clock: new Clock(Noon));
        await auth.InitializeAsync();
        Assert.False(auth.IsAuthenticated);
        Assert.Equal("recovery_required", auth.Session.RecoveryStatus);
        Assert.NotNull(await store.LoadAsync());
        provider.Status = HttpStatusCode.OK;
        await auth.SendBusinessAsync(new(HttpMethod.Get, "https://api.etrade.com/v1/accounts/list"), () => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        Assert.True(auth.IsAuthenticated);
        provider.Status = HttpStatusCode.Unauthorized;
        provider.Body = "oauth_problem=token_rejected";
        await Assert.ThrowsAsync<OAuthProviderException>(() => auth.RenewAsync());
        Assert.False(auth.IsAuthenticated);
        Assert.Null(await store.LoadAsync());
    }

    [Fact]
    public async Task UnspecifiedAuthorizationFailure_PreservesCredentialsAndRecovers()
    {
        var store = new FailingStore { Value = Credentials };
        var provider = new Provider { Status = HttpStatusCode.Unauthorized, Body = "oauth_problem=signature_invalid&raw=secret" };
        using var client = new HttpClient(provider);
        var auth = new EtradeOAuth1AuthenticationHandler(client, new() { ConsumerKey = "key", ConsumerSecret = "secret" }, store, clock: new Clock(Noon));
        await auth.InitializeAsync();
        Assert.Equal("recovery_required", auth.Session.RecoveryStatus);
        Assert.NotNull(store.Value);
        var tools = new EtradeOAuthMcpTools(auth);
        var failed = await tools.RenewOAuthAsync();
        Assert.DoesNotContain("secret", failed);
        Assert.NotNull(store.Value);
        provider.Status = HttpStatusCode.OK;
        await auth.RenewAsync();
        await Assert.ThrowsAsync<EtradeOperationException>(() => auth.SendBusinessAsync(new(HttpMethod.Get, "https://api.etrade.com/v1/accounts/list"),
            () => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("signature invalid secret") })));
        Assert.NotNull(store.Value);
        await auth.RenewAsync();
        Assert.True(auth.IsAuthenticated);
    }

    [Fact]
    public async Task RenewalSaveFailure_PreservesOldMetadataAndRequiresRecovery()
    {
        var store = new FailingStore { Value = Credentials };
        using var client = new HttpClient(new Provider());
        var clock = new Clock(Noon);
        var auth = new EtradeOAuth1AuthenticationHandler(client, new() { ConsumerKey = "key", ConsumerSecret = "secret" }, store, clock: clock);
        await auth.InitializeAsync();
        store.FailSave = true;
        clock.Now = Noon.AddMinutes(111);
        var tools = new EtradeOAuthMcpTools(auth);
        var failed = await tools.RenewOAuthAsync();
        Assert.Contains("\"success\":false", failed);
        Assert.DoesNotContain("secret", failed);
        Assert.False(auth.IsAuthenticated);
        Assert.Equal(Noon, store.Value!.RenewedAt);
        store.FailSave = false;
        await auth.RenewAsync();
        Assert.Equal(clock.Now, store.Value.RenewedAt);
        Assert.Equal(Credentials.ExpiresAt, store.Value.ExpiresAt);
    }

    [Fact]
    public async Task DefinitiveRestorationFailure_DeletesCredentialsAndStartsUnauthenticated()
    {
        var store = new FailingStore { Value = Credentials };
        using var client = new HttpClient(new Provider { Status = HttpStatusCode.Unauthorized, Body = "oauth_problem=token_expired" });
        var auth = new EtradeOAuth1AuthenticationHandler(client, new() { ConsumerKey = "key", ConsumerSecret = "secret" }, store, clock: new Clock(Noon));
        await auth.InitializeAsync();
        Assert.False(auth.IsAuthenticated);
        Assert.Null(store.Value);
        Assert.Equal("invalidated", auth.Session.RecoveryStatus);
    }

    [Theory]
    [InlineData("2026-03-08T06:30:00Z", "2026-03-09T04:00:00Z")]
    [InlineData("2026-11-01T05:30:00Z", "2026-11-02T05:00:00Z")]
    [InlineData("2026-09-26T16:00:00Z", "2026-09-27T04:00:00Z")]
    public void Midnight_UsesEasternDaylightSaving(string issued, string expected) =>
        Assert.Equal(DateTimeOffset.Parse(expected), EtradeOAuth1AuthenticationHandler.MidnightEastern(DateTimeOffset.Parse(issued)));

    [Fact]
    public async Task Midnight_DeletesWithoutRenewing()
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = new StoreFixture();
        using var store = new EncryptedFileTokenStore(fixture.Config);
        await store.SaveAsync(Credentials);
        var network = new Provider();
        using var client = new HttpClient(network);
        var auth = new EtradeOAuth1AuthenticationHandler(client, fixture.Config, store, clock: new Clock(Credentials.ExpiresAt));
        await auth.InitializeAsync();
        Assert.Equal(0, network.Calls);
        Assert.Null(await store.LoadAsync());
        Assert.False(auth.IsAuthenticated);
    }

    private sealed class FailingStore : ITokenStore
    {
        public bool FailSave, FailDelete;
        public OAuthCredentials? Value;
        public Task<OAuthCredentials?> LoadAsync() => Task.FromResult(Value);
        public Task SaveAsync(OAuthCredentials value) { if (FailSave) throw new InvalidOperationException("secret"); Value = value; return Task.CompletedTask; }
        public Task DeleteAsync() { if (FailDelete) throw new EtradeOperationException("OAuth credentials cleared locally, but stored credential deletion failed."); Value = null; return Task.CompletedTask; }
    }

    [Fact]
    public async Task StatusRefresh_ExpiresStoredAuthorizationWithoutProviderRequest()
    {
        var store = new FailingStore { Value = Credentials };
        var provider = new Provider();
        var clock = new Clock(Noon);
        using var client = new HttpClient(provider);
        var auth = new EtradeOAuth1AuthenticationHandler(client, new() { ConsumerKey = "fixture", ConsumerSecret = "fixture" }, store, clock: clock);
        await auth.InitializeAsync();
        Assert.True(auth.IsAuthenticated);
        var calls = provider.Calls;
        clock.Now = Credentials.ExpiresAt;
        await auth.RefreshStatusAsync();
        Assert.Null(store.Value);
        Assert.False(auth.IsAuthenticated);
        Assert.Equal("expired", auth.Session.RecoveryStatus);
        Assert.Equal(calls, provider.Calls);
    }

    [Fact]
    public async Task StatusRefresh_ClearsExpiredPendingOwnerFlowWithoutProviderRequest()
    {
        var provider = new Provider();
        var clock = new Clock(Noon);
        using var client = new HttpClient(provider);
        var auth = new EtradeOAuth1AuthenticationHandler(client, new() { ConsumerKey = "fixture", ConsumerSecret = "fixture" }, new FailingStore(), clock: clock);
        await auth.StartAsync();
        Assert.NotNull(auth.Session.AuthorizationUrl);
        clock.Now = Noon.AddMinutes(10);
        await auth.RefreshStatusAsync();
        Assert.Null(auth.Session.AuthorizationUrl);
        await Assert.ThrowsAsync<EtradeOperationException>(() => auth.CompleteAsync("expired-verifier"));
        Assert.Equal(1, provider.Calls);
    }

    [Fact]
    public async Task PersistenceFailure_DoesNotReportAuthenticationSuccess_RevocationFailureClearsLocally()
    {
        var store = new FailingStore { FailSave = true };
        using var client = new HttpClient(new Provider());
        var auth = new EtradeOAuth1AuthenticationHandler(client, new() { ConsumerKey = "key", ConsumerSecret = "secret" }, store, clock: new Clock(Noon));
        var tools = new EtradeOAuthMcpTools(auth);
        await tools.StartOAuthAsync();
        var failed = await tools.CompleteOAuthAsync("verifier");
        Assert.Contains("\"success\":false", failed);
        Assert.DoesNotContain("secret", failed);
        Assert.False(auth.IsAuthenticated);
        store.FailSave = false;
        await tools.CompleteOAuthAsync("verifier");
        store.FailDelete = true;
        var revoked = await tools.RevokeOAuthAsync();
        Assert.Contains("\"success\":false", revoked);
        Assert.Contains("deletion failed", revoked);
        Assert.False(auth.IsAuthenticated);
        await Assert.ThrowsAsync<EtradeOperationException>(() => auth.SendBusinessAsync(new(HttpMethod.Get, "https://api.etrade.com/v1/accounts/list"), () => throw new Exception()));
    }
    [Fact]
    public async Task PendingOwnerFlow_IsSerializedAndExpiresWithoutTransmission()
    {
        var store=new FailingStore();var provider=new Provider();using var client=new HttpClient(provider);var clock=new Clock(Noon);
        var auth=new EtradeOAuth1AuthenticationHandler(client,new(){ConsumerKey="fixture",ConsumerSecret="fixture"},store,clock:clock);
        await auth.StartAsync();await Assert.ThrowsAsync<EtradeOperationException>(()=>auth.StartAsync());Assert.Equal(1,provider.Calls);
        clock.Now=Noon.AddMinutes(10);await Assert.ThrowsAsync<EtradeOperationException>(()=>auth.CompleteAsync("expired-verifier"));Assert.Equal(1,provider.Calls);
        await auth.StartAsync();await auth.CompleteAsync("fresh-verifier");Assert.True(auth.IsAuthenticated);
    }

}
