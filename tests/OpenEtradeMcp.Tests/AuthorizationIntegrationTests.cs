using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenEtradeMcp.Authorization;
using OpenEtradeMcp.Contracts;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace OpenEtradeMcp.Tests;

public sealed class AuthorizationIntegrationTests
{
    private sealed class Factory : WebApplicationFactory<AuthorizationEntryPoint>
    {
        public string Root = Path.Combine(Path.GetTempPath(), "etrade-auth-" + Guid.NewGuid());
        public Dictionary<string,string?> Settings;
        public bool RetainRoot;
        public Factory(string? reuse = null)
        {
            if (reuse != null) { Root = reuse; Settings = JsonSerializer.Deserialize<Dictionary<string,string?>>(File.ReadAllText(Root + "/settings.json"))!; return; }
            Directory.CreateDirectory(Root);
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=authorization", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
            File.WriteAllBytes(Root + "/cert.pfx", cert.Export(X509ContentType.Pfx)); File.WriteAllText(Root + "/ca.crt", cert.ExportCertificatePem());
            File.WriteAllText(Root + "/assertion.pem", rsa.ExportRSAPrivateKeyPem()); File.WriteAllText(Root + "/google-secret", "fixture-no-provider");
            Settings = new() {
                ["Tls:Certificate"]=Root+"/cert.pfx", ["Tls:Ca"]=Root+"/ca.crt", ["StateFile"]=Root+"/state.db",
                ["Issuer"]="https://example.test", ["Resource"]="https://example.test/mcp", ["OwnerSubject"]="owner-google-subject",
                ["TokenSigningCertificate"]=Root+"/cert.pfx", ["TokenEncryptionCertificate"]=Root+"/cert.pfx",
                ["AssertionPrivateKey"]=Root+"/assertion.pem", ["GoogleClientId"]="fixture", ["GoogleClientSecretFile"]=Root+"/google-secret",
                ["DataProtectionDirectory"]=Root+"/dp", ["IdentityFetchUrl"]="https://identity-proxy:3128", ["GatewayUrl"]="https://gateway:8443"
            };
            File.WriteAllText(Root + "/settings.json", JsonSerializer.Serialize(Settings));
            var options = new DbContextOptionsBuilder<State>().UseSqlite("Data Source="+Root+"/state.db").UseOpenIddict().Options;
            using var db = new State(options); db.Database.EnsureCreated();
        }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            foreach(var pair in Settings) builder.UseSetting(pair.Key, pair.Value);
            builder.ConfigureServices(s => s.AddSingleton<IStartupFilter, PeerFilter>());
        }
        public HttpClient Http(string peer="ingress", bool owner=false)
        {
            var client = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress=new Uri("https://example.test"), AllowAutoRedirect=false, HandleCookies=false });
            client.DefaultRequestHeaders.Add("X-Test-Peer", peer);
            if (owner)
            {
                var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(IdentityConstants.ApplicationScheme);
                var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "owner")); identity.AddClaim(new Claim("google_subject", "owner-google-subject"));
                identity.AddClaim(new Claim("mfa_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
                var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), new AuthenticationProperties { IssuedUtc=DateTimeOffset.UtcNow, ExpiresUtc=DateTimeOffset.UtcNow.AddMinutes(5) }, IdentityConstants.ApplicationScheme);
                client.DefaultRequestHeaders.Add("Cookie", options.Cookie.Name + "=" + options.TicketDataFormat.Protect(ticket));
            }
            return client;
        }
        protected override void Dispose(bool disposing) { base.Dispose(disposing); if(disposing && !RetainRoot && Directory.Exists(Root)) Directory.Delete(Root,true); }
    }
    // Test transport only: emulate certificates that Kestrel has already validated, never expose this in production.
    private sealed class PeerFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app => {
            app.Use(async(ctx,n) => {
                using var rsa=RSA.Create(2048); var req=new CertificateRequest("CN="+ctx.Request.Headers["X-Test-Peer"],rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                ctx.Connection.ClientCertificate=req.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddHours(1));
                await n();
            }); next(app);
        };
    }
    private static async Task<string> Enroll(Factory factory,string client,string agent)
    {
        using var scope=factory.Services.CreateScope(); var db=scope.ServiceProvider.GetRequiredService<State>();
        var manager=scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(new OpenIddictApplicationDescriptor { ClientId=client,ClientType=ClientTypes.Public,
            RedirectUris={new Uri("https://client.test/callback")}, Permissions={Permissions.Endpoints.Authorization,Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,Permissions.GrantTypes.RefreshToken,Permissions.ResponseTypes.Code,Permissions.Prefixes.Scope+"etrade.read",Permissions.Prefixes.Resource+"https://example.test/mcp"},
            Requirements={Requirements.Features.ProofKeyForCodeExchange} });
        db.Clients.Add(new ApprovedClient {Id=client,Active=true,PlatformIdentity="fixture",RedirectsJson="[\"https://client.test/callback\"]"});
        var grant=new AgentGrant {AgentId=agent,ClientId=client,Active=true,ExpiresAt=DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds()};
        db.Grants.Add(grant);await db.SaveChangesAsync();return grant.Id;
    }
    private static string AuthorizeUrl(string client,string challenge,string redirect="https://client.test/callback",string method="S256",string scope="etrade.read offline_access",string resource="https://example.test/mcp") =>
        "/connect/authorize?response_type=code&client_id="+client+"&redirect_uri="+Uri.EscapeDataString(redirect)+"&scope="+Uri.EscapeDataString(scope)+
        "&resource="+Uri.EscapeDataString(resource)+"&code_challenge="+challenge+"&code_challenge_method="+method+"&state=fixture";
    private static async Task<(string Code,string Verifier)> Code(Factory f,string client)
    {
        var verifier=new string('a',64);
        var challenge=Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        using var http=f.Http(owner:true);var url=AuthorizeUrl(client,challenge);
        using var get=await http.GetAsync(url);Assert.True(get.StatusCode == HttpStatusCode.OK, await get.Content.ReadAsStringAsync());
        var html=await get.Content.ReadAsStringAsync();var token=System.Text.RegularExpressions.Regex.Match(html,"name='__RequestVerificationToken' value='([^']+)'").Groups[1].Value;
        var csrf=get.Headers.GetValues("Set-Cookie").Single(c=>c.StartsWith("__Host-csrf=")).Split(';')[0];
        var fields = System.Web.HttpUtility.ParseQueryString(new Uri("https://example.test" + url).Query);
        var formFields = fields.AllKeys.ToDictionary(k => k!, k => fields[k]!); formFields["__RequestVerificationToken"] = token;
        using var post=new HttpRequestMessage(HttpMethod.Post,url) {Content=new FormUrlEncodedContent(formFields)};
        post.Headers.Add("Cookie",string.Join("; ",http.DefaultRequestHeaders.GetValues("Cookie")) + "; " + csrf);
        using var result=await http.SendAsync(post);Assert.True(result.StatusCode == HttpStatusCode.Redirect,await result.Content.ReadAsStringAsync());
        var query=System.Web.HttpUtility.ParseQueryString(result.Headers.Location!.Query);
        Assert.Null(query["error"]);return(query["code"]!,verifier);
    }
    private static async Task<JsonElement> Exchange(HttpClient http,string client,string code,string verifier)
    {
        using var response=await http.PostAsync("/connect/token",new FormUrlEncodedContent(new Dictionary<string,string>{
            ["grant_type"]="authorization_code",["client_id"]=client,["code"]=code,["code_verifier"]=verifier,["redirect_uri"]="https://client.test/callback"}));
        var body=await response.Content.ReadAsStringAsync(); Assert.True(response.IsSuccessStatusCode,body);return JsonDocument.Parse(body).RootElement.Clone();
    }
    [Fact]
    public async Task OAuth_PKCE_CodeReplay_RefreshReuse_AndRevocation()
    {
        using var f=new Factory(); var a=await Enroll(f,"client-a","agent-a");var b=await Enroll(f,"client-b","agent-b");
        var (code,verifier)=await Code(f,"client-a");using var ingress=f.Http();var tokens=await Exchange(ingress,"client-a",code,verifier);
        Assert.InRange(tokens.GetProperty("expires_in").GetInt32(),299,300);
        using var replay=await ingress.PostAsync("/connect/token",new FormUrlEncodedContent(new Dictionary<string,string>{["grant_type"]="authorization_code",["client_id"]="client-a",["code"]=code,["code_verifier"]=verifier,["redirect_uri"]="https://client.test/callback"}));
        Assert.False(replay.IsSuccessStatusCode);
        // Code replay may invalidate that token family; mint a fresh approved connection for refresh checks.
        (code,verifier)=await Code(f,"client-a");tokens=await Exchange(ingress,"client-a",code,verifier);
        var refresh=tokens.GetProperty("refresh_token").GetString()!;
        async Task<HttpResponseMessage> Refresh()=>await ingress.PostAsync("/connect/token",new FormUrlEncodedContent(new Dictionary<string,string>{["grant_type"]="refresh_token",["client_id"]="client-a",["refresh_token"]=refresh}));
        using var first=await Refresh();Assert.True(first.IsSuccessStatusCode,await first.Content.ReadAsStringAsync());
        using var second=await Refresh();Assert.False(second.IsSuccessStatusCode);
        using var scope=f.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<State>();
        Assert.False((await db.Grants.FindAsync(a))!.Active);Assert.True((await db.Grants.FindAsync(b))!.Active);
    }
    [Fact]
    public async Task Assertions_PersistConsumption_RecheckRevocation_AndRejectWrongPeerOrBearerAtConsume()
    {
        using var f=new Factory();var grant=await Enroll(f,"client-a","agent-a");var(code,verifier)=await Code(f,"client-a");
        using var ingress=f.Http();var tokens=await Exchange(ingress,"client-a",code,verifier);
        using var mcp=f.Http("mcp");mcp.DefaultRequestHeaders.Authorization=new("Bearer",tokens.GetProperty("access_token").GetString());
        var request=new AssertionRequest(new(1,ReadOperation.listAccounts,new()));
        async Task<string> Issue() { using var r=await mcp.PostAsync("/internal/assertions",new StringContent(JsonSerializer.Serialize(request,StrictJson.Options),Encoding.UTF8,"application/json"));
            var body=await r.Content.ReadAsStringAsync();Assert.True(r.IsSuccessStatusCode,r.StatusCode + " " + body);return JsonDocument.Parse(body).RootElement.GetProperty("assertion").GetString()!; }
        var assertion=await Issue();using var gateway=f.Http("gateway");
        async Task<HttpResponseMessage> Consume(string value)=>await gateway.PostAsync("/internal/consume",new StringContent(JsonSerializer.Serialize(new ConsumeRequest(value),StrictJson.Options),Encoding.UTF8,"application/json"));
        using var consumed=await Consume(assertion);Assert.True(consumed.IsSuccessStatusCode);
        using var replay=await Consume(assertion);Assert.Equal(HttpStatusCode.Unauthorized,replay.StatusCode);
        assertion=await Issue();
        using(var scope=f.Services.CreateScope()){var db=scope.ServiceProvider.GetRequiredService<State>();await db.Grants.Where(g=>g.Id==grant).ExecuteUpdateAsync(s=>s.SetProperty(g=>g.Active,false));}
        using var revoked=await Consume(assertion);Assert.Equal(HttpStatusCode.Unauthorized,revoked.StatusCode);
        using var denied=await mcp.PostAsync("/internal/validate",null);Assert.Equal(HttpStatusCode.Unauthorized,denied.StatusCode);
        using var publicAttempt=await ingress.PostAsync("/internal/consume",null);Assert.Equal(HttpStatusCode.Forbidden,publicAttempt.StatusCode);
    }
    [Fact]
    public async Task InvalidPkceRedirectResourceAndScope_CannotIssueCodes()
    {
        using var f=new Factory();await Enroll(f,"client-a","agent-a");using var http=f.Http(owner:true);
        foreach(var url in new[]{AuthorizeUrl("client-a","plain",method:"plain"),AuthorizeUrl("client-a","x",redirect:"https://evil.test/"),
            AuthorizeUrl("client-a","x",scope:"trade"),AuthorizeUrl("client-a","x",resource:"https://evil.test/mcp")})
        {using var result=await http.GetAsync(url);var location=result.Headers.Location?.ToString()??"";Assert.DoesNotContain("code=",location);Assert.NotEqual(HttpStatusCode.OK,result.StatusCode);}
        using var admin=f.Http(owner:true);using var csrf=await admin.PostAsync("/owner/grants",new StringContent("{}"));Assert.False(csrf.IsSuccessStatusCode);
        using var unauth=f.Http();using var denied=await unauth.GetAsync("/owner/audit");Assert.Equal(HttpStatusCode.Unauthorized,denied.StatusCode);
    }
    [Fact]
    public async Task Owner_MfaRecoveryIsSingleUseAndSubjectPinned()
    {
        using var f=new Factory(); using var scope=f.Services.CreateScope(); var users=scope.ServiceProvider.GetRequiredService<UserManager<Owner>>();
        var owner=new Owner {UserName="owner",GoogleSubject="owner-google-subject",EmailConfirmed=true};
        Assert.True((await users.CreateAsync(owner)).Succeeded); await users.ResetAuthenticatorKeyAsync(owner); await users.SetTwoFactorEnabledAsync(owner,true);
        var recovery=(await users.GenerateNewTwoFactorRecoveryCodesAsync(owner,2))!.First();
        string ExternalCookie(string subject) {
            var options=f.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(IdentityConstants.ExternalScheme);
            var identity=new ClaimsIdentity(IdentityConstants.ExternalScheme); identity.AddClaim(new Claim(ClaimTypes.NameIdentifier,subject));
            var ticket=new AuthenticationTicket(new ClaimsPrincipal(identity),new AuthenticationProperties {IssuedUtc=DateTimeOffset.UtcNow,ExpiresUtc=DateTimeOffset.UtcNow.AddMinutes(5)},IdentityConstants.ExternalScheme);
            return options.Cookie.Name+"="+options.TicketDataFormat.Protect(ticket);
        }
        async Task<HttpStatusCode> Attempt(string subject,string code) {
            using var http=f.Http();var external=ExternalCookie(subject);http.DefaultRequestHeaders.Add("Cookie",external);
            using var get=await http.GetAsync("/owner/mfa");var html=await get.Content.ReadAsStringAsync();
            var token=System.Text.RegularExpressions.Regex.Match(html,"name='__RequestVerificationToken' value='([^']+)'").Groups[1].Value;
            var csrf=get.Headers.GetValues("Set-Cookie").Single(c=>c.StartsWith("__Host-csrf=")).Split(';')[0];
            using var post=new HttpRequestMessage(HttpMethod.Post,"/owner/mfa") {Content=new FormUrlEncodedContent(new Dictionary<string,string>{["code"]=code,["__RequestVerificationToken"]=token})};
            post.Headers.Add("Cookie",external+"; "+csrf);using var result=await http.SendAsync(post);return result.StatusCode;
        }
        Assert.Equal(HttpStatusCode.Forbidden,await Attempt("wrong-google-subject",recovery));
        Assert.Equal(HttpStatusCode.Forbidden,await Attempt("owner-google-subject","invalid"));
        Assert.Equal(HttpStatusCode.Redirect,await Attempt("owner-google-subject",recovery));
        Assert.Equal(HttpStatusCode.Forbidden,await Attempt("owner-google-subject",recovery));
        var secret=await users.GetAuthenticatorKeyAsync(owner);
        Assert.True(await users.VerifyTwoFactorTokenAsync(owner,TokenOptions.DefaultAuthenticatorProvider,Totp(secret!)));
    }
    private static string Totp(string secret)
    {
        var alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; var bytes=new List<byte>(); int bits=0,value=0;
        foreach(var letter in secret.ToUpperInvariant()) {value=(value<<5)|alphabet.IndexOf(letter);bits+=5;if(bits>=8){bits-=8;bytes.Add((byte)(value>>bits));}}
        var counter=new byte[8];System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter,DateTimeOffset.UtcNow.ToUnixTimeSeconds()/30);
        using var hmac=new HMACSHA1(bytes.ToArray());var digest=hmac.ComputeHash(counter);var offset=digest[^1]&15;
        var number=(System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(digest.AsSpan(offset,4))&0x7fffffff)%1000000;
        return number.ToString("D6",System.Globalization.CultureInfo.InvariantCulture);
    }
    [Fact]
    public async Task InvalidExpiredAndUnapprovedTokensFailClosed_IndependentAgentRemainsUsable()
    {
        using var f=new Factory();await Enroll(f,"client-a","agent-a");await Enroll(f,"client-b","agent-b");
        var(aCode,aVerifier)=await Code(f,"client-a");var(bCode,bVerifier)=await Code(f,"client-b");using var ingress=f.Http();
        var a=await Exchange(ingress,"client-a",aCode,aVerifier);var b=await Exchange(ingress,"client-b",bCode,bVerifier);
        using var mcp=f.Http("mcp");
        async Task<HttpStatusCode> Validate(string token) {
            using var message=new HttpRequestMessage(HttpMethod.Post,"/internal/validate");message.Headers.Authorization=new("Bearer",token);
            using var response=await mcp.SendAsync(message);return response.StatusCode;
        }
        var aToken=a.GetProperty("access_token").GetString()!;var bToken=b.GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.Unauthorized,await Validate("invalid-external-token"));Assert.Equal(HttpStatusCode.OK,await Validate(aToken));
        using(var scope=f.Services.CreateScope()) {
            var db=scope.ServiceProvider.GetRequiredService<State>();await db.Clients.Where(c=>c.Id=="client-a").ExecuteUpdateAsync(s=>s.SetProperty(c=>c.Active,false));
        }
        Assert.Equal(HttpStatusCode.Unauthorized,await Validate(aToken));Assert.Equal(HttpStatusCode.OK,await Validate(bToken));
        using(var scope=f.Services.CreateScope()) {
            var manager=scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();var token=await manager.FindByReferenceIdAsync(bToken);
            var descriptor=new OpenIddictTokenDescriptor();await manager.PopulateAsync(descriptor,token!);descriptor.ExpirationDate=DateTimeOffset.UtcNow.AddSeconds(-1);await manager.UpdateAsync(token!,descriptor);
        }
        Assert.Equal(HttpStatusCode.Unauthorized,await Validate(bToken));
        // Missing authentication database must not recreate approved state or authorize a token.
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();File.Move(f.Root+"/state.db",f.Root+"/state.offline");
        Assert.NotEqual(HttpStatusCode.OK,await Validate(aToken));
    }

    [Fact]
    public async Task ConsumedAssertion_RemainsRejectedAfterAuthorizationRestart()
    {
        using var first=new Factory();await Enroll(first,"client-a","agent-a");var(code,verifier)=await Code(first,"client-a");
        using var ingress=first.Http();var token=await Exchange(ingress,"client-a",code,verifier);
        using var mcp=first.Http("mcp");mcp.DefaultRequestHeaders.Authorization=new("Bearer",token.GetProperty("access_token").GetString());
        using var issued=await mcp.PostAsync("/internal/assertions",new StringContent(JsonSerializer.Serialize(new AssertionRequest(new(1,ReadOperation.listAccounts,new())),StrictJson.Options),Encoding.UTF8,"application/json"));
        Assert.True(issued.IsSuccessStatusCode);var assertion=JsonDocument.Parse(await issued.Content.ReadAsStringAsync()).RootElement.GetProperty("assertion").GetString()!;
        using var gateway=first.Http("gateway");
        using var consumed=await gateway.PostAsync("/internal/consume",new StringContent(JsonSerializer.Serialize(new ConsumeRequest(assertion),StrictJson.Options),Encoding.UTF8,"application/json"));Assert.True(consumed.IsSuccessStatusCode);
        first.RetainRoot=true;first.Dispose();using var second=new Factory(first.Root);using var restartedGateway=second.Http("gateway");
        using var replay=await restartedGateway.PostAsync("/internal/consume",new StringContent(JsonSerializer.Serialize(new ConsumeRequest(assertion),StrictJson.Options),Encoding.UTF8,"application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized,replay.StatusCode);
    }

    [Fact]
    public async Task CredentialReplacement_RequiresOwnerRecentMfaAndCsrfAndRecordsExactVersions()
    {
        using var f=new Factory();using var owner=f.Http(owner:true);
        using var get=await owner.GetAsync("/owner/mfa");var html=await get.Content.ReadAsStringAsync();
        var token=System.Text.RegularExpressions.Regex.Match(html,"name='__RequestVerificationToken' value='([^']+)'").Groups[1].Value;
        var csrf=get.Headers.GetValues("Set-Cookie").Single(c=>c.StartsWith("__Host-csrf=")).Split(';')[0];
        using var request=new HttpRequestMessage(HttpMethod.Post,"/owner/credentials/approve") {Content=new StringContent("{\"versions\":{\"consumer-key\":\"2\",\"consumer-secret\":\"3\",\"token-key\":\"4\"}}",Encoding.UTF8,"application/json")};
        request.Headers.Add("RequestVerificationToken",token);request.Headers.Add("Cookie",string.Join("; ",owner.DefaultRequestHeaders.GetValues("Cookie"))+"; "+csrf);
        using var approved=await owner.SendAsync(request);Assert.True(approved.IsSuccessStatusCode);
        using var scope=f.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<State>();var approval=await db.MaintenanceApprovals.SingleAsync();
        Assert.False(approval.Consumed);Assert.InRange(approval.ExpiresAt-DateTimeOffset.UtcNow.ToUnixTimeSeconds(),299,300);
        Assert.Equal("3",JsonDocument.Parse(approval.VersionsJson).RootElement.GetProperty("consumer-secret").GetString());
        using var publicClient=f.Http();using var denied=await publicClient.PostAsync("/owner/credentials/approve",new StringContent("{}"));Assert.Equal(HttpStatusCode.Unauthorized,denied.StatusCode);
        using var noCsrf=await owner.PostAsync("/owner/credentials/approve",new StringContent("{}"));Assert.False(noCsrf.IsSuccessStatusCode);
    }

}
