using System.Net;
using MesaShield.Core.Privacy;
using Xunit;

namespace MesaShield.Tests;

public sealed class PrivacyGuardTests
{
    [Theory]
    [InlineData("bazaar.abuse.ch", NetworkPurpose.SignatureUpdate)]
    [InlineData("www.virustotal.com", NetworkPurpose.CloudReputation)]
    [InlineData("api.github.com", NetworkPurpose.AppUpdate)]
    [InlineData("example.com", NetworkPurpose.Other)]
    public void Classifies_Hosts(string host, NetworkPurpose expected) =>
        Assert.Equal(expected, PrivacyGuard.Classify(host));

    [Fact]
    public void Standard_Allows_Everything()
    {
        var g = new PrivacyGuard { Mode = PrivacyMode.Standard };
        Assert.True(g.Evaluate("www.virustotal.com").Allowed);
        Assert.True(g.Evaluate("bazaar.abuse.ch").Allowed);
    }

    [Fact]
    public void Strict_Blocks_Only_Cloud_Reputation()
    {
        var g = new PrivacyGuard { Mode = PrivacyMode.Strict };
        Assert.False(g.Evaluate("www.virustotal.com").Allowed);
        Assert.True(g.Evaluate("bazaar.abuse.ch").Allowed);
        Assert.True(g.Evaluate("api.github.com").Allowed);
    }

    [Fact]
    public void Offline_Blocks_Everything()
    {
        var g = new PrivacyGuard { Mode = PrivacyMode.Offline };
        Assert.False(g.Evaluate("bazaar.abuse.ch").Allowed);
        Assert.False(g.Evaluate("api.github.com").Allowed);
        Assert.False(g.Evaluate("www.virustotal.com").Allowed);
    }

    [Fact]
    public void Records_An_Audit_Entry_Per_Decision()
    {
        var g = new PrivacyGuard { Mode = PrivacyMode.Strict };
        var entries = new List<NetworkAuditEntry>();
        g.Decision += entries.Add;
        g.Evaluate("www.virustotal.com");
        g.Evaluate("bazaar.abuse.ch");
        Assert.Equal(2, entries.Count);
        Assert.False(entries[0].Allowed);
        Assert.True(entries[1].Allowed);
    }

    [Fact]
    public async Task Handler_Blocks_Requests_In_Offline_Mode()
    {
        var g = new PrivacyGuard { Mode = PrivacyMode.Offline };
        using var client = new HttpClient(new PrivacyHandler(g, new SucceedHandler()));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("https://bazaar.abuse.ch/x"));
    }

    [Fact]
    public async Task Handler_Allows_Requests_In_Standard_Mode()
    {
        var g = new PrivacyGuard { Mode = PrivacyMode.Standard };
        using var client = new HttpClient(new PrivacyHandler(g, new SucceedHandler()));
        var resp = await client.GetAsync("https://bazaar.abuse.ch/x");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private sealed class SucceedHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}
