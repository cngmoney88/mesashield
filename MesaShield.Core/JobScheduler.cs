namespace MesaShield.Core;

/// <summary>
/// A lightweight in-process scheduler that fires callbacks when scheduled jobs come
/// due. It checks every minute against the app's Schedule definitions and persists
/// LastRunUtc so a missed window (machine asleep) runs on next wake rather than never.
/// </summary>
public sealed class JobScheduler : IDisposable
{
    private readonly AppSettings _settings;
    private readonly Func<Task> _onSignatureUpdate;
    private readonly Func<Task> _onScheduledScan;
    private readonly Func<Task> _onUpdateCheck;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public JobScheduler(
        AppSettings settings,
        Func<Task> onSignatureUpdate,
        Func<Task> onScheduledScan,
        Func<Task> onUpdateCheck)
    {
        _settings = settings;
        _onSignatureUpdate = onSignatureUpdate;
        _onScheduledScan = onScheduledScan;
        _onUpdateCheck = onUpdateCheck;
    }

    public void Start() => _loop ??= Task.Run(() => LoopAsync(_cts.Token));

    private async Task LoopAsync(CancellationToken ct)
    {
        // A small initial delay so startup isn't competing with a scheduled job.
        try { await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        while (!ct.IsCancellationRequested)
        {
            var now = DateTimeOffset.Now;
            await MaybeRun(_settings.SignatureUpdateSchedule, now, _onSignatureUpdate).ConfigureAwait(false);
            await MaybeRun(_settings.ScanSchedule, now, _onScheduledScan).ConfigureAwait(false);
            if (_settings.AutoUpdateEnabled)
                await MaybeRun(_settings.UpdateCheckSchedule, now, _onUpdateCheck).ConfigureAwait(false);

            try { await Task.Delay(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>True if the schedule is due at <paramref name="now"/> given its last run.</summary>
    public static bool IsDue(Schedule schedule, DateTimeOffset now)
    {
        if (schedule.Frequency == ScheduleFrequency.Off) return false;

        var anchor = schedule.LastRunUtc?.ToLocalTime() ?? now.AddYears(-1);
        var next = schedule.NextRun(anchor);
        return next is not null && next.Value <= now;
    }

    private async Task MaybeRun(Schedule schedule, DateTimeOffset now, Func<Task> action)
    {
        if (!IsDue(schedule, now)) return;
        try
        {
            await action().ConfigureAwait(false);
        }
        catch
        {
            // A failing job shouldn't kill the scheduler; it'll retry next window.
        }
        finally
        {
            schedule.LastRunUtc = DateTimeOffset.UtcNow;
            _settings.Save();
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}
