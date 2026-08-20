namespace MesaShield.Core.Ml;

/// <summary>
/// Welford's online algorithm for running mean/variance — updates one sample at a time
/// with no stored history, so a machine can learn "normal" continuously in a few bytes.
/// Supports exponential forgetting so the model adapts as the machine's normal drifts.
/// </summary>
public sealed class OnlineStat
{
    public long Count { get; private set; }
    public double Mean { get; private set; }
    private double _m2;

    /// <summary>Forgetting factor in (0,1]; 1 = never forget. 0.999 fades old data slowly.</summary>
    public double Decay { get; init; } = 1.0;

    public double Variance => Count > 1 ? _m2 / (Count - 1) : 0;
    public double StdDev => Math.Sqrt(Variance);

    public void Add(double value)
    {
        if (Decay < 1.0 && Count > 0)
        {
            // Exponentially fade the accumulated statistics before adding the new sample.
            _m2 *= Decay;
        }
        Count++;
        var delta = value - Mean;
        Mean += delta / Count;
        _m2 += delta * (value - Mean);
    }

    /// <summary>How many standard deviations <paramref name="value"/> is from the mean (0 if not enough data).</summary>
    public double ZScore(double value)
    {
        var sd = StdDev;
        return sd > 1e-9 ? Math.Abs(value - Mean) / sd : 0;
    }

    public (long Count, double Mean, double M2) Snapshot() => (Count, Mean, _m2);

    public static OnlineStat FromSnapshot(long count, double mean, double m2, double decay) =>
        new() { Count = count, Mean = mean, _m2 = m2, Decay = decay };
}
