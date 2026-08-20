using MesaShield.Core.Ml;
using MesaShield.Core.Net;
using Xunit;

namespace MesaShield.Tests;

public sealed class EssentialServicesTests
{
    [Fact] public void Dns_Port_Is_Infra() => Assert.True(EssentialServices.IsInfraPort(53));
    [Fact] public void Https_Port_Is_Not_Infra() => Assert.False(EssentialServices.IsInfraPort(443));
    [Fact] public void Svchost_Is_System() => Assert.True(EssentialServices.IsSystemProcess("svchost.exe"));
    [Fact] public void Random_App_Is_Not_System() => Assert.False(EssentialServices.IsSystemProcess("invoice.exe"));

    [Theory]
    [InlineData("download.windowsupdate.com", true)]
    [InlineData("time.windows.com", true)]
    [InlineData("evil-exfil.example", false)]
    public void Matches_Essential_Hosts(string host, bool essential) =>
        Assert.Equal(essential, EssentialServices.IsEssentialHost(host));
}

public sealed class EgressGuardTests
{
    private static NetworkObservation Obs(string proc, string ip, int port = 443) =>
        new() { ProcessName = proc, RemoteAddress = ip, RemotePort = port };

    private static EgressGuard Warmed(EgressMode mode)
    {
        var learner = new NetworkAnomalyLearner { WarmUpObservations = 20 };
        var guard = new EgressGuard(learner) { Mode = mode };
        // Teach it that "browser -> 93.184.216.34:443" is normal.
        for (var i = 0; i < 30; i++) guard.Evaluate(Obs("browser", "93.184.216.34"));
        return guard;
    }

    [Fact]
    public void Local_Traffic_Always_Allowed()
    {
        var guard = Warmed(EgressMode.Enforce);
        Assert.Equal(EgressAction.Allow, guard.Evaluate(Obs("anything", "192.168.1.9")).Action);
    }

    [Fact]
    public void Essential_Services_Allowed_Even_In_Enforce()
    {
        var guard = Warmed(EgressMode.Enforce);
        Assert.Equal(EgressAction.Allow, guard.Evaluate(Obs("svchost", "20.1.2.3", 443)).Action);      // system process
        Assert.Equal(EgressAction.Allow, guard.Evaluate(Obs("anything", "9.9.9.9", 53)).Action);        // DNS port
    }

    [Fact]
    public void Enforce_Blocks_New_External_Destination()
    {
        var guard = Warmed(EgressMode.Enforce);
        var d = guard.Evaluate(Obs("invoice", "45.83.12.9"));
        Assert.Equal(EgressAction.Block, d.Action);
        Assert.False(d.Essential);
    }

    [Fact]
    public void Observe_Only_Watches_Never_Blocks()
    {
        var guard = Warmed(EgressMode.Observe);
        var d = guard.Evaluate(Obs("invoice", "45.83.12.9"));
        Assert.Equal(EgressAction.Watch, d.Action);
    }

    [Fact]
    public void Known_Destination_Allowed()
    {
        var guard = Warmed(EgressMode.Enforce);
        Assert.Equal(EgressAction.Allow, guard.Evaluate(Obs("browser", "93.184.216.34")).Action);
    }

    [Fact]
    public void Large_Upload_To_New_Host_Flags_Exfiltration()
    {
        var guard = Warmed(EgressMode.Enforce);
        var d = guard.Evaluate(Obs("backup", "45.83.12.9"), bytesOut: 20L * 1024 * 1024);
        Assert.Equal(EgressAction.Block, d.Action);
        Assert.Contains("exfiltration", d.Reason);
    }

    [Fact]
    public void User_Approval_Overrides_To_Allow()
    {
        var guard = Warmed(EgressMode.Enforce);
        var o = Obs("invoice", "45.83.12.9");
        guard.Approve(o);
        Assert.Equal(EgressAction.Allow, guard.Evaluate(o).Action);
    }

    [Fact]
    public void User_Block_Overrides_To_Block()
    {
        var guard = Warmed(EgressMode.Observe);
        var o = Obs("browser", "93.184.216.34");
        guard.Deny(o);
        Assert.Equal(EgressAction.Block, guard.Evaluate(o).Action);
    }

    [Fact]
    public void Approve_Block_Lists_Roundtrip()
    {
        var path = Path.Combine(Path.GetTempPath(), $"egress-{System.Guid.NewGuid():N}.json");
        var guard = new EgressGuard(new NetworkAnomalyLearner()) { Mode = EgressMode.Enforce };
        guard.Approve(Obs("app", "1.2.3.4"));
        guard.Save(path);

        var reloaded = new EgressGuard(new NetworkAnomalyLearner());
        reloaded.Load(path);
        Assert.True(reloaded.IsApproved(Obs("app", "1.2.3.4")));
        Assert.Equal(EgressMode.Enforce, reloaded.Mode);
        File.Delete(path);
    }
}
