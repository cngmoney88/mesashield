using MesaShield.Core;
using Xunit;

namespace MesaShield.Tests;

public sealed class FleetTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("mesashield-fleet-").FullName;

    private MachineStatus Sample(string name, bool rt = true, long alerts = 0) => new()
    {
        MachineName = name,
        Version = "0.6.0",
        RealTimeProtection = rt,
        SignatureCount = 1_000_000,
        RecentAlerts24h = alerts,
    };

    [Fact]
    public void Health_Rollup_Reflects_State()
    {
        Assert.Equal("protected", Sample("A").Health);
        Assert.Equal("at-risk", Sample("B", rt: false).Health);
        Assert.Equal("attention", Sample("C", alerts: 3).Health);
    }

    [Fact]
    public void Reporter_Writes_Local_And_Shared()
    {
        var shared = Path.Combine(_dir, "share");
        var local = Path.Combine(_dir, "status.json");
        var reporter = new FleetReporter(local, () => Sample("SHOP-PC-1")) { SharedFolder = shared };
        reporter.Report();

        Assert.True(File.Exists(local));
        Assert.True(File.Exists(Path.Combine(shared, "SHOP-PC-1.json")));
    }

    [Fact]
    public void Reader_Aggregates_All_Machines()
    {
        var shared = Path.Combine(_dir, "share2");
        new FleetReporter(Path.Combine(_dir, "a.json"), () => Sample("PC-A")) { SharedFolder = shared }.Report();
        new FleetReporter(Path.Combine(_dir, "b.json"), () => Sample("PC-B", rt: false)) { SharedFolder = shared }.Report();

        var all = FleetReader.ReadAll(shared);
        Assert.Equal(2, all.Count);
        Assert.Equal("PC-A", all[0].MachineName);
        Assert.Equal("at-risk", all[1].Health);
    }

    [Fact]
    public void Stale_Detection_Works()
    {
        var fresh = Sample("X");
        Assert.False(fresh.IsStale(TimeSpan.FromMinutes(30)));
        var old = fresh with { ReportedUtc = DateTimeOffset.UtcNow.AddHours(-2) };
        Assert.True(old.IsStale(TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public void Filename_Is_Sanitized()
    {
        Assert.Equal("SHOP_PC_1.json", FleetReporter.StatusFileName("SHOP PC 1"));
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }
}
