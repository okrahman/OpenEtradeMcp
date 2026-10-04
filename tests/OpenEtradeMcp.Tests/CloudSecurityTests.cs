using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Server;
using OpenEtradeMcp.Contracts;
using OpenEtradeMcp.Gateway;
using OpenEtradeMcp.Authorization;
using OpenEtradeMcp.Server;
namespace OpenEtradeMcp.Tests;

public sealed class CloudSecurityTests
{
    private static ReadRequest Accounts => new(1, ReadOperation.listAccounts, new());
    private sealed class Clock : TimeProvider { public DateTimeOffset Now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    [Fact]
    public void ExactDiscovery_AdapterHasTenReadsAndNoBrokerageDependency()
    {
        var services = new ServiceCollection(); services.AddLogging(); services.AddMcpServer().WithTools<ReadTools>();
        using var sp = services.BuildServiceProvider();
        Assert.Equal(RequestPolicy.Rules.Keys.Select(k => k.ToString()).Order(), sp.GetServices<McpServerTool>().Select(t => t.ProtocolTool.Name).Order());
        Assert.DoesNotContain(typeof(ReadTools).Assembly.GetReferencedAssemblies(), a => a.Name == "OpenEtradeMcp");
    }
    [Fact]
    public void ProductionConfiguration_RejectsLegacySelection()
    {
        var config = new ETradeConfig(); Assert.Equal("https://api.etrade.com/v1", config.BaseUrl);
        Assert.Throws<EtradeOperationException>(() => config.UseSandbox = true);
    }
    [Theory]
    [InlineData("POST", "https://api.etrade.com/v1/accounts/a/orders/place")]
    [InlineData("POST", "https://api.etrade.com/v1/accounts/a/orders/preview")]
    [InlineData("PUT", "https://api.etrade.com/v1/accounts/a/orders/1/change/preview")]
    [InlineData("GET", "https://apisb.etrade.com/v1/accounts/list.json")]
    [InlineData("GET", "https://127.0.0.1/v1/accounts/list.json")]
    [InlineData("GET", "https://api.etrade.com/v1/accounts/a%2fb/balance.json")]
    [InlineData("GET", "https://api.etrade.com/v1/accounts/list.json?url=https%3A%2F%2Fevil.test")]
    [InlineData("GET", "https://api.etrade.com/v1/accounts/a/orders.json?count=1&count=2")]
    public async Task Transmission_DeniesBeforeNetwork(string method, string url)
    {
        var network = new Network(); using var client = new HttpClient(new TransmissionPolicy { InnerHandler = network });
        await Assert.ThrowsAsync<PolicyException>(() => client.SendAsync(new(new HttpMethod(method), url)));
        Assert.Equal(0, network.Calls);
    }
    private sealed class Network : HttpMessageHandler {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) { Calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)); }
    }
    [Fact]
    public void AllTenRoutes_AreCanonicalProductionReads()
    {
        foreach (var (operation, rule) in RequestPolicy.Rules)
        {
            var args = rule.Parameters.Where(p => p.Required).ToDictionary(p => p.Name, p => p.Values.Length > 0 ? p.Values[0] : p.Type == "integer" ? "1" : "IBM");
            var read = new ReadRequest(1, operation, args); var uri = RequestPolicy.Route(read);
            Assert.Equal("api.etrade.com", uri.Host); RequestPolicy.ValidateOutgoing(new(HttpMethod.Get, uri));
        }
    }
    [Theory]
    [InlineData("{\"version\":1,\"version\":1,\"operation\":\"listAccounts\",\"arguments\":{}}")]
    [InlineData("{\"version\":1,\"operation\":\"listAccounts\",\"arguments\":{},\"url\":\"evil\"}")]
    [InlineData("{\"version\":1,\"operation\":\"listOrders\",\"arguments\":{\"accountIdKey\":\"a\",\"accountIdKey\":\"b\"}}")]
    public void AmbiguousJson_RejectsDuplicateOrUnknownFields(string json) => Assert.ThrowsAny<Exception>(() => StrictJson.Parse<ReadRequest>(Encoding.UTF8.GetBytes(json)));
    [Fact]
    public void Assertions_RejectTamperingSubstitutionExternalTypeAndExpiration()
    {
        using var rsa = RSA.Create(2048); using var other = RSA.Create(2048); var clock = new Clock();
        var assertions = new Assertions(rsa, "https://example.test", clock);
        var token = assertions.Issue(new("agent", "grant", "client", "origin"), Accounts);
        assertions.Verify(token, Accounts);
        Assert.ThrowsAny<Exception>(() => new Assertions(other, "https://example.test", clock).Verify(token));
        Assert.ThrowsAny<Exception>(() => new Assertions(rsa, "https://wrong.test", clock).Verify(token));
        Assert.ThrowsAny<Exception>(() => assertions.Verify(token, new(1, ReadOperation.getQuotes, new() { ["symbols"] = "IBM" })));
        var parts = token.Split('.'); parts[1] = parts[1][..^1] + (parts[1][^1] == 'A' ? 'B' : 'A');
        Assert.ThrowsAny<Exception>(() => assertions.Verify(string.Join('.', parts)));
        Assert.ThrowsAny<Exception>(() => assertions.Verify("external-token"));
        var now=clock.Now.UtcDateTime;
        var wrongAudience=new System.IdentityModel.Tokens.Jwt.JwtSecurityToken("https://example.test","wrong-gateway",null,now,now.AddSeconds(10),new(new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa),Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256));
        wrongAudience.Header["typ"]=Assertions.Type;
        Assert.ThrowsAny<Exception>(()=>assertions.Verify(new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(wrongAudience)));
        var wrongType=new System.IdentityModel.Tokens.Jwt.JwtSecurityToken("https://example.test",Assertions.Audience,null,now,now.AddSeconds(10),new(new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa),Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256));
        wrongType.Header["typ"]="at+jwt";
        Assert.ThrowsAny<Exception>(()=>assertions.Verify(new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(wrongType)));
        clock.Now = clock.Now.AddSeconds(10); Assert.ThrowsAny<Exception>(() => assertions.Verify(token));
    }
    [Fact]
    public void RateAndConcurrency_EnforceAgentAndGlobalLimits()
    {
        var clock = new Clock(); var limits = new ReadLimits(clock);
        using var a1 = limits.TryAcquire("a"); using var a2 = limits.TryAcquire("a"); Assert.Null(limits.TryAcquire("a"));
        using var b1 = limits.TryAcquire("b"); using var b2 = limits.TryAcquire("b"); Assert.Null(limits.TryAcquire("c"));
        a1!.Dispose(); a2!.Dispose(); b1!.Dispose(); b2!.Dispose();
        for (int i=0;i<28;i++) using(limits.TryAcquire("a")) { }
        Assert.Null(limits.TryAcquire("a")); clock.Now = clock.Now.AddMinutes(1); using var allowed = limits.TryAcquire("a"); Assert.NotNull(allowed);
    }
    [Theory]
    [InlineData("127.0.0.1")][InlineData("169.254.169.254")][InlineData("10.0.0.1")][InlineData("172.16.0.1")]
    [InlineData("192.168.1.1")][InlineData("::1")][InlineData("fe80::1")][InlineData("fc00::1")][InlineData("::ffff:127.0.0.1")]
    public void Cimd_RejectsNonpublicAddresses(string address) => Assert.False(Cimd.PublicAddress(IPAddress.Parse(address)));
    [Theory]
    [InlineData("http://example.test/client.json")][InlineData("https://127.0.0.1/client.json")][InlineData("https://example.test:444/client.json")]
    [InlineData("https://user@example.test/client.json")][InlineData("https://example.test/client.json#part")]
    public void Cimd_RequiresExactHttps(string url) => Assert.Throws<PolicyException>(() => Cimd.ExactHttps(url));
}
