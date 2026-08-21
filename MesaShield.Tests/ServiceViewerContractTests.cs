using System.Text.Json;
using MesaShield.Core;
using Xunit;

namespace MesaShield.Tests;

/// <summary>
/// The desktop app, when the always-on service is running, becomes a viewer and reads the machine
/// status the service writes to status.json. These tests lock that on-disk contract: what the
/// service serializes must be exactly what the viewer can read back.
/// </summary>
public sealed class ServiceViewerContractTests
{
    // Mirrors FleetReporter's writer options (indented) and the viewer's default reader.
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    [Fact]
    public void MachineStatus_Roundtrips_Through_The_Status_File()
    {
        var original = new MachineStatus
        {
            MachineName = "SHOP-1",
            Version = "0.19.0",
            RealTimeProtection = true,
            BehaviorGuard = true,
            ProcessMonitoring = true,
            DeepMonitoring = true,
            Elevated = true,
            EgressMode = "Enforce",
            EgressBlocks24h = 3,
            PrivacyMode = "Standard",
            SignatureCount = 1_234_567,
            ThreatsHandled = 42,
            InQuarantine = 5,
            RecentAlerts24h = 7,
            LearnerLearning = false,
            LearnerObservations = 9001,
        };

        var json = JsonSerializer.Serialize(original, WriteOptions);
        var readBack = JsonSerializer.Deserialize<MachineStatus>(json);   // viewer uses default options

        Assert.NotNull(readBack);
        Assert.Equal("SHOP-1", readBack!.MachineName);
        Assert.Equal("0.19.0", readBack.Version);
        Assert.True(readBack.RealTimeProtection);
        Assert.True(readBack.DeepMonitoring);
        Assert.Equal("Enforce", readBack.EgressMode);
        Assert.Equal(1_234_567, readBack.SignatureCount);
        Assert.Equal(42, readBack.ThreatsHandled);
        Assert.Equal(5, readBack.InQuarantine);
    }

    [Fact]
    public void Viewer_Reads_Protection_State_The_Service_Reports_Off()
    {
        var offline = new MachineStatus
        {
            MachineName = "SHOP-2",
            Version = "0.19.0",
            RealTimeProtection = false,
        };
        var json = JsonSerializer.Serialize(offline, WriteOptions);
        var s = JsonSerializer.Deserialize<MachineStatus>(json);
        Assert.NotNull(s);
        Assert.False(s!.RealTimeProtection);   // viewer must faithfully show "Off", not assume "On"
    }
}
