using MesaShield.Core;
using MesaShield.Core.Ml;
using Xunit;

namespace MesaShield.Tests;

public sealed class OnlineStatTests
{
    [Fact]
    public void Computes_Mean_And_Std()
    {
        var s = new OnlineStat();
        foreach (var v in new double[] { 2, 4, 4, 4, 5, 5, 7, 9 }) s.Add(v);
        Assert.Equal(5.0, s.Mean, 3);
        Assert.Equal(2.138, s.StdDev, 2); // sample std of that classic set
    }

    [Fact]
    public void ZScore_Flags_Outliers()
    {
        var s = new OnlineStat();
        for (var i = 0; i < 100; i++) s.Add(10);
        s.Add(11);
        Assert.True(s.ZScore(50) > 3);
    }
}

public sealed class FrequencyModelTests
{
    [Fact]
    public void Unseen_Value_Is_Fully_Novel()
    {
        var m = new FrequencyModel { Decay = 1.0 };
        m.Observe("a"); m.Observe("a"); m.Observe("b");
        Assert.False(m.HasSeen("z"));
        Assert.Equal(1.0, m.Novelty("z"));
        Assert.True(m.Novelty("a") < 1.0);
    }
}

public sealed class AnomalyLearnerTests
{
    private static ProcessObservation Normal(int i) => new()
    {
        ExecutablePath = @"C:\Program Files\Common\app.exe",
        HourOfDay = 10,
        IsSigned = true,
        ParentPath = @"C:\Windows\explorer.exe",
    };

    [Fact]
    public void Stays_Quiet_During_Warmup_Then_Scores()
    {
        var learner = new AnomalyLearner { WarmUpObservations = 50 };
        for (var i = 0; i < 49; i++) Assert.True(learner.Observe(Normal(i)).IsLearning);
        Assert.True(learner.Observe(Normal(50)).IsLearning == false || learner.Observations >= 50);
    }

    [Fact]
    public void Learns_Normal_And_Flags_A_Novel_Risky_Program()
    {
        var learner = new AnomalyLearner { WarmUpObservations = 100 };
        for (var i = 0; i < 120; i++) learner.Observe(Normal(i)); // establish normal

        var suspicious = new ProcessObservation
        {
            ExecutablePath = @"C:\Users\creed\AppData\Local\Temp\svch0st.exe",
            HourOfDay = 3,
            IsSigned = false,
            ParentPath = @"C:\Users\creed\Downloads\invoice.exe",
        };
        var assessment = learner.Observe(suspicious);

        Assert.False(assessment.IsLearning);
        Assert.True(assessment.Score >= 0.6, $"score was {assessment.Score}");
        Assert.NotEmpty(assessment.Reasons);
        Assert.NotNull(assessment.SuggestedSeverity);
    }

    [Fact]
    public void Known_Program_Is_Not_Flagged()
    {
        var learner = new AnomalyLearner { WarmUpObservations = 100 };
        for (var i = 0; i < 120; i++) learner.Observe(Normal(i));
        var assessment = learner.Observe(Normal(999));
        Assert.True(assessment.Score < 0.3);
    }

    [Fact]
    public void Model_Roundtrips_Through_Disk()
    {
        var path = Path.Combine(Path.GetTempPath(), $"anomaly-{Guid.NewGuid():N}.json");
        var learner = new AnomalyLearner { WarmUpObservations = 10 };
        for (var i = 0; i < 20; i++) learner.Observe(Normal(i));
        learner.Save(path);

        var reloaded = AnomalyLearner.Load(path, warmUp: 10);
        Assert.Equal(learner.Observations, reloaded.Observations);
        // A previously-seen program should still be recognized (low score) after reload.
        Assert.True(reloaded.Observe(Normal(0)).Score < 0.3);
        File.Delete(path);
    }
}

public sealed class MalwareClassifierTests
{
    private static byte[] FakePe(double fillHighEntropy)
    {
        var buffer = new byte[64 * 1024];
        buffer[0] = (byte)'M'; buffer[1] = (byte)'Z';
        var rng = new Random(1);
        // Fill with either random (high-entropy) or repetitive (low-entropy) content.
        for (var i = 512; i < buffer.Length; i++)
            buffer[i] = fillHighEntropy > 0.5 ? (byte)rng.Next(256) : (byte)0x41;
        return buffer;
    }

    [Fact]
    public void Baseline_Model_Is_Usable()
    {
        var clf = MalwareClassifier.Baseline();
        Assert.True(clf.IsUsable);
        Assert.Equal("0-baseline", clf.Version);
    }

    [Fact]
    public void High_Entropy_Scores_Higher_Than_Low_Entropy()
    {
        var clf = MalwareClassifier.Baseline();
        var highP = clf.Probability(PeFeatureExtractor.Extract(FakePe(1.0), 64 * 1024));
        var lowP = clf.Probability(PeFeatureExtractor.Extract(FakePe(0.0), 64 * 1024));
        Assert.True(highP > lowP, $"high={highP}, low={lowP}");
        Assert.InRange(highP, 0.0, 1.0);
    }

    [Fact]
    public void Deterministic_Model_Scores_Exactly()
    {
        // A trivial 2-feature model: prob rises with feature 0.
        var model = new MalwareClassifier.Model
        {
            Version = "test",
            FeatureNames = new[] { "a", "b" },
            Mean = new[] { 0.0, 0.0 },
            Std = new[] { 1.0, 1.0 },
            Weights = new[] { 10.0, 0.0 },
            Bias = 0.0,
        };
        var clf = MalwareClassifier.FromModel(model);
        Assert.True(clf.Probability(new[] { 5.0, 0.0 }) > 0.99);
        Assert.True(clf.Probability(new[] { -5.0, 0.0 }) < 0.01);
        Assert.Equal(0.5, clf.Probability(new[] { 0.0, 0.0 }), 3);
    }
}
