using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using OpenEtradeMcp.Contracts;
using OpenEtradeMcp.Server;
namespace OpenEtradeMcp.Tests;
public sealed class AdapterTests
{
    private sealed class Network(Func<HttpRequestMessage,Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct) {Calls++;return send(request);}
    }
    [Fact]
    public async Task Bearer_RemainsInAuthorizationCallsAndNeverReachesGateway()
    {
        const string external="fixture-external-bearer-must-not-reach-gateway";
        var auth=new Network(async request=> {
            Assert.Equal("Bearer",request.Headers.Authorization!.Scheme);Assert.Equal(external,request.Headers.Authorization.Parameter);
            if(request.RequestUri!.AbsolutePath=="/internal/validate")return new(HttpStatusCode.OK){Content=new StringContent("{}")};
            var body=await request.Content!.ReadAsStringAsync();Assert.DoesNotContain(external,body);
            return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new AssertionReply("internal-assertion"),StrictJson.Options),Encoding.UTF8,"application/json")};
        });
        var gateway=new Network(async request=> {
            Assert.Null(request.Headers.Authorization);Assert.Equal("/internal/read",request.RequestUri!.AbsolutePath);
            var body=await request.Content!.ReadAsStringAsync();Assert.DoesNotContain(external,body);
            var payload=StrictJson.Parse<GatewayRequest>(Encoding.UTF8.GetBytes(body));Assert.Equal("internal-assertion",payload.Assertion);
            Assert.Equal(ReadOperation.listAccounts,payload.Request.Operation);
            return new(HttpStatusCode.OK){Content=new StringContent("{\"fixture\":true}")};
        });
        using var connections=new AdapterConnections(new HttpClient(auth){BaseAddress=new("https://authorization:8443")},new HttpClient(gateway){BaseAddress=new("https://gateway:8443")});
        var ctx=new DefaultHttpContext();ctx.Request.Headers.Authorization="Bearer "+external;
        using var adapter=new GatewayAdapter(new HttpContextAccessor{HttpContext=ctx},connections);
        Assert.True(await adapter.AuthenticateAsync(ctx));Assert.Contains("fixture",await adapter.ReadAsync(new(1,ReadOperation.listAccounts,new())));
        Assert.Equal(2,auth.Calls);Assert.Equal(1,gateway.Calls);
        await Assert.ThrowsAsync<PolicyException>(()=>adapter.ReadAsync(new(1,(ReadOperation)999,new())));
        Assert.Equal(2,auth.Calls);Assert.Equal(1,gateway.Calls);
    }
    [Fact]
    public async Task AuthorizationUnavailable_ProducesNoGatewayRequest()
    {
        var auth=new Network(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        var gateway=new Network(_=>throw new Exception("Gateway must not be invoked"));
        using var connections=new AdapterConnections(new HttpClient(auth){BaseAddress=new("https://authorization:8443")},new HttpClient(gateway){BaseAddress=new("https://gateway:8443")});
        var ctx=new DefaultHttpContext();ctx.Request.Headers.Authorization="Bearer fixture";
        using var adapter=new GatewayAdapter(new HttpContextAccessor{HttpContext=ctx},connections);
        await Assert.ThrowsAsync<ModelContextProtocol.McpException>(()=>adapter.ReadAsync(new(1,ReadOperation.listAccounts,new())));
        Assert.Equal(0,gateway.Calls);
    }
}
