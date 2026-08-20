using MesaShield.Core.Ml;
using Xunit;

namespace MesaShield.Tests;

public sealed class BenignModelTests
{
    // Build a cluster of "normal software" feature vectors, then check an outlier is flagged.
    private static List<double[]> NormalCluster(int n)
    {
        var rng = new Random(7);
        var list = new List<double[]>();
        for (var i = 0; i < n; i++)
        {
            list.Add(new[]
            {
                6.0 + rng.NextDouble(),      // size_log ~6-7
                6.2 + rng.NextDouble() * 0.4,// entropy moderate
                1.0,                          // is_pe
                5 + rng.Next(3),              // sections
                0.0,                          // not high entropy
                0.0,
                0.02 + rng.NextDouble() * 0.01,
                0.4 + rng.NextDouble() * 0.1,
                0.2 + rng.NextDouble() * 0.1,
                1.0 + rng.Next(2),
            });
        }
        return list;
    }

    [Fact]
    public void Fits_And_Flags_Outliers_Not_Normal_Files()
    {
        var model = BenignAnomalyModel.FromModel(BenignAnomalyModel.Fit(NormalCluster(300), "test"));
        Assert.True(model.IsUsable);

        // A file that looks like normal software → low distance, not flagged.
        var normal = new[] { 6.5, 6.3, 1.0, 6.0, 0.0, 0.0, 0.025, 0.45, 0.25, 1.0 };
        Assert.True(model.Distance(normal) < model.Distance(new[] { 3.0, 7.95, 1.0, 20.0, 1.0, 0.0, 0.0002, 0.02, 0.6, 12.0 }));

        // A packed, tiny, high-entropy, import-heavy PE → far from the known-good profile.
        var weird = new[] { 3.0, 7.95, 1.0, 20.0, 1.0, 0.0, 0.0002, 0.02, 0.6, 12.0 };
        Assert.True(model.Distance(weird) >= 4.0, $"distance {model.Distance(weird)}");
    }

    [Fact]
    public void Fit_Requires_Samples()
    {
        Assert.Throws<System.ArgumentException>(() => BenignAnomalyModel.Fit(new List<double[]>(), "x"));
    }
}
