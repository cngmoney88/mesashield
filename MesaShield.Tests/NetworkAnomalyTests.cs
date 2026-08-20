using MesaShield.Core.Ml;
using Xunit;

namespace MesaShield.Tests;

public sealed class NetworkAnomalyTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("192.168.1.5", false)]
    [InlineData("10.0.0.3", false)]
    [InlineData("172.16.4.4", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.1.1", false)]
    public void Classifies_External_Vs_Local(string ip, bool external)
    {
        Assert.Equal(external, new NetworkObservation { ProcessName = "x", RemoteAddress = ip }.IsExternal);
    }

    [Fact]
    public void Ignores_Local_Traffic()
    {
        var learner = new NetworkAnomalyLearner { WarmUpObservations = 5 };
        var a = learner.Observe(new NetworkObservation { ProcessName = "app", RemoteAddress = "192.168.1.10", RemotePort = 445 });
        Assert.Equal(0, a.Score);
    }

    [Fact]
    public void Learns_Normal_Endpoints_Then_Flags_A_New_One()
    {
        var learner = new NetworkAnomalyLearner { WarmUpObservations = 20 };
        // Establish normal: browser talks to a CDN on 443.
        for (var i = 0; i < 30; i++)
            learner.Observe(new NetworkObservation { ProcessName = "browser", RemoteAddress = "93.184.216.34", RemotePort = 443 });

        var suspicious = learner.Observe(new NetworkObservation
        {
            ProcessName = "invoice", RemoteAddress = "45.83.12.9", RemotePort = 4444,
        });

        Assert.False(suspicious.IsLearning);
        Assert.True(suspicious.Score >= 0.6, $"score {suspicious.Score}");
        Assert.NotEmpty(suspicious.Reasons);
    }

    [Fact]
    public void Known_Endpoint_Not_Flagged()
    {
        var learner = new NetworkAnomalyLearner { WarmUpObservations = 20 };
        for (var i = 0; i < 30; i++)
            learner.Observe(new NetworkObservation { ProcessName = "browser", RemoteAddress = "93.184.216.34", RemotePort = 443 });
        var again = learner.Observe(new NetworkObservation { ProcessName = "browser", RemoteAddress = "93.184.216.34", RemotePort = 443 });
        Assert.True(again.Score < 0.3);
    }

    [Fact]
    public void Roundtrips_Through_Disk()
    {
        var path = Path.Combine(Path.GetTempPath(), $"net-{Guid.NewGuid():N}.json");
        var learner = new NetworkAnomalyLearner { WarmUpObservations = 5 };
        for (var i = 0; i < 10; i++)
            learner.Observe(new NetworkObservation { ProcessName = "app", RemoteAddress = "8.8.8.8", RemotePort = 443 });
        learner.Save(path);
        var reloaded = NetworkAnomalyLearner.Load(path, warmUp: 5);
        Assert.Equal(learner.Observations, reloaded.Observations);
        Assert.True(reloaded.Observe(new NetworkObservation { ProcessName = "app", RemoteAddress = "8.8.8.8", RemotePort = 443 }).Score < 0.3);
        File.Delete(path);
    }
}
