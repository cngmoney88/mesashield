using MesaShield.Core;
using Xunit;

namespace MesaShield.Tests;

public sealed class FleetCommanderTests : IDisposable
{
    private readonly string _shared = Directory.CreateTempSubdirectory("mesashield-fleet-").FullName;

    [Fact]
    public void Command_Targeted_At_Machine_Is_Pending_For_It_Only()
    {
        FleetCommander.Issue(_shared, FleetCommandType.QuickScan, target: "SHOP-1");
        Assert.Single(FleetCommander.Pending(_shared, "SHOP-1"));
        Assert.Empty(FleetCommander.Pending(_shared, "SHOP-2"));
    }

    [Fact]
    public void Wildcard_Command_Is_Pending_For_All_Machines()
    {
        FleetCommander.Issue(_shared, FleetCommandType.UpdateSignatures, target: "*");
        Assert.Single(FleetCommander.Pending(_shared, "SHOP-1"));
        Assert.Single(FleetCommander.Pending(_shared, "SHOP-2"));
    }

    [Fact]
    public void Ack_Removes_It_From_Pending_For_That_Machine_Only()
    {
        FleetCommander.Issue(_shared, FleetCommandType.FullScan, target: "*");
        var cmd = FleetCommander.Pending(_shared, "SHOP-1").Single();
        FleetCommander.Ack(_shared, cmd.Id, "SHOP-1");

        Assert.Empty(FleetCommander.Pending(_shared, "SHOP-1"));   // acked
        Assert.Single(FleetCommander.Pending(_shared, "SHOP-2"));  // still pending elsewhere
    }

    [Fact]
    public void Carries_An_Argument()
    {
        FleetCommander.Issue(_shared, FleetCommandType.SetEgressMode, target: "SHOP-1", arg: "Enforce");
        var cmd = FleetCommander.Pending(_shared, "SHOP-1").Single();
        Assert.Equal(FleetCommandType.SetEgressMode, cmd.Type);
        Assert.Equal("Enforce", cmd.Arg);
    }

    [Fact]
    public void Status_Health_Reflects_State()
    {
        Assert.Equal("at-risk", new MachineStatus { MachineName = "m", Version = "1", RealTimeProtection = false }.Health);
        Assert.Equal("attention", new MachineStatus { MachineName = "m", Version = "1", RealTimeProtection = true, RecentAlerts24h = 3 }.Health);
        Assert.Equal("protected", new MachineStatus { MachineName = "m", Version = "1", RealTimeProtection = true, SignatureCount = 100 }.Health);
    }

    [Fact]
    public void Reader_Reads_Back_Written_Status()
    {
        var reporter = new FleetReporter(Path.Combine(_shared, "local.json"),
            () => new MachineStatus { MachineName = "SHOP-1", Version = "0.15.0", RealTimeProtection = true, SignatureCount = 5, EgressMode = "Enforce" })
        { SharedFolder = Path.Combine(_shared, "status") };
        reporter.Report();

        var all = FleetReader.ReadAll(Path.Combine(_shared, "status"));
        var s = Assert.Single(all);
        Assert.Equal("SHOP-1", s.MachineName);
        Assert.Equal("Enforce", s.EgressMode);
    }

    public void Dispose() { try { Directory.Delete(_shared, true); } catch { } }
}
