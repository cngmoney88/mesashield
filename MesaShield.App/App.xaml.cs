using System.IO;
using System.Reflection;
using System.Windows;
using MesaShield.Core;
using MesaShield.Core.Incidents;
using MesaShield.Core.Ml;
using MesaShield.Core.Net;
using MesaShield.Core.Privacy;
using MesaShield.Windows;

namespace MesaShield.App;

public partial class App : System.Windows.Application
{
    /// <summary>All MesaShield state lives under %LocalAppData%\MesaShield.</summary>
    public static string DataDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MesaShield");

    public static string SettingsPath => Path.Combine(DataDirectory, "settings.json");

    public static SemVer CurrentVersion { get; } = ResolveVersion();
    public static bool StartMinimized { get; private set; }

    /// <summary>The one shared engine. The app hosts it in-process; the Windows Service hosts the
    /// same class headless. There is a single implementation of what MesaShield does.</summary>
    public static ShieldEngineHost Host { get; private set; } = null!;

    // ---- Thin forwarders so existing UI code keeps addressing App.X ----
    public static AppSettings Settings => Host.Settings;
    public static SignatureDatabase Signatures => Host.Signatures;
    public static ScanEngine Engine => Host.Engine;
    public static QuarantineManager Quarantine => Host.Quarantine;
    public static ShieldEventLog EventLog => Host.EventLog;
    public static IncidentStore Incidents => Host.Incidents;
    public static SignatureUpdater Updater => Host.Updater;
    public static UpdateChecker AppUpdater => Host.AppUpdater;
    public static ReputationClient Reputation => Host.Reputation;
    public static AmsiScanner Amsi => Host.Amsi;
    public static RealTimeProtector RealTime => Host.RealTime;
    public static ProcessWatcher ProcessWatch => Host.ProcessWatch;
    public static UsbWatcher Usb => Host.Usb;
    public static FirewallManager Firewall => Host.Firewall;
    public static BehaviorMonitor BehaviorWatch => Host.BehaviorWatch;
    public static AnomalyLearner Learner => Host.Learner;
    public static NetworkAnomalyLearner NetworkLearner => Host.NetworkLearner;
    public static EgressGuard Egress => Host.Egress;
    public static EgressWatcher EgressWatch => Host.EgressWatch;
    public static MalwareClassifier? Classifier => Host.Classifier;
    public static BenignAnomalyModel? BenignModel => Host.BenignModel;
    public static EtwMonitor Etw => Host.Etw;
    public static FleetReporter Fleet => Host.Fleet;
    public static PrivacyGuard Privacy => Host.Privacy;
    public static long ThreatsHandledTotal => Host.ThreatsHandledTotal;

    public static string SignaturesDirectory => Host.SignaturesDirectory;
    public static string PrivacyAuditPath => Host.PrivacyAuditPath;
    public static string EgressStatePath => Host.EgressStatePath;
    public static string BenignModelPath => Host.BenignModelPath;
    public static string StatusPathLocal => Host.StatusPathLocal;

    public static Task RecordIncidentAsync(string kind, string message, string? file, string? threat)
        => Host.RecordIncidentAsync(kind, message, file, threat);
    public static string[] QuickScanTargets() => Host.QuickScanTargets();
    public static void ReloadBenignModel() => Host.ReloadBenignModel();
    public static void EraseAllLearnedData() => Host.EraseAllLearnedData();

    private static Mutex? _singleInstance;
    private static EventWaitHandle? _showSignal;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Self-install on first run from anywhere that isn't the install location.
        // Done before the single-instance guard so the transient installer never holds the lock.
        if (Installer.EnsureInstalled(e.Args, out _))
        {
            Shutdown();
            return;
        }

        // Single instance: only ever one app and one window.
        _singleInstance = new Mutex(false, "MesaShield.SingleInstance.v1");
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, "MesaShield.ShowWindow.v1");
        bool owns;
        try { owns = _singleInstance.WaitOne(TimeSpan.Zero); }
        catch (AbandonedMutexException) { owns = true; }
        if (!owns)
        {
            _showSignal.Set();
            Shutdown();
            return;
        }
        new Thread(() =>
        {
            while (_showSignal!.WaitOne())
                Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.BringToFront());
        }) { IsBackground = true, Name = "MesaShield-ShowListener" }.Start();

        StartMinimized = e.Args.Contains("--minimized") || e.Args.Contains("--silent");
        Directory.CreateDirectory(DataDirectory);

        var settings = AppSettings.Load(SettingsPath);

        // Managed deployment: apply an admin-supplied config shipped next to the app or in
        // %ProgramData%\MesaShield. Applied every start so central config stays authoritative.
        foreach (var configPath in new[]
                 {
                     Path.Combine(Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? "", DeployConfig.FileName),
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MesaShield", DeployConfig.FileName),
                 })
        {
            DeployConfig.Load(configPath)?.ApplyTo(settings);
        }

        // If the always-on service is protecting this PC, the app runs as a viewer — it never
        // double-runs the watchers, ETW session, or scheduler.
        bool serviceActive = false;
        try { serviceActive = ServiceControl.IsRunning(); } catch { }

        Host = new ShieldEngineHost(DataDirectory, CurrentVersion, settings);
        WireHostEvents(Host);
        await Host.InitializeAsync(passive: serviceActive);

        // Keep the run-at-startup registry entry in sync with the setting.
        try
        {
            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (exePath is not null) StartupManager.SetEnabled(settings.RunAtStartup, exePath);
        }
        catch { /* non-fatal */ }
    }

    /// <summary>Marshal every engine event onto the UI thread and hand it to the window.</summary>
    private void WireHostEvents(ShieldEngineHost h)
    {
        void UI(Action a) => Current.Dispatcher.Invoke(a);
        MainWindow? W() => Current.MainWindow as MainWindow;

        h.ThreatHandled += (finding, quarantined) => UI(() => W()?.OnThreatHandled(finding, quarantined));
        h.ProcessBlocked += finding => UI(() => W()?.OnProcessBlocked(finding));
        h.BehaviorAlert += alert => UI(() => W()?.OnBehaviorAlert(alert));
        h.IncidentRecorded += incident => UI(() => W()?.OnIncident(incident));
        h.EgressDecision += d => UI(() => W()?.OnEgressDecision(d));
        h.UsbInserted += root => UI(() => W()?.OnUsbInserted(root));
        h.Anomaly += (obs, a) => UI(() => W()?.NotifyAnomaly(obs, a));
        h.DeepAnomaly += (a, ctx) => UI(() => W()?.NotifyDeepAnomaly(a, ctx));
        h.TamperHealed += name => UI(() => W()?.NotifyTamper(name));
        h.FirstRunStarted += () => UI(() => W()?.NotifyFirstRunStarted());
        h.FirstRunDone += count => UI(() => W()?.NotifyFirstRunDone(count));
        h.ScheduledScanDone += summary => UI(() => W()?.NotifyScheduledScanDone(summary));
        h.UpdateAvailable += release => UI(() => W()?.NotifyUpdateAvailable(release));
        h.UpdateReadyToInstall += (dest, version) => UI(() => OnUpdateReady(dest, version));
    }

    /// <summary>A verified newer installer is ready — launch it silently and bow out for the swap.</summary>
    private void OnUpdateReady(string dest, string version)
    {
        try
        {
            _ = EventLog.LogAsync("update", $"Auto-installing update v{version} (silent).");
            if (SelfUpdater.LaunchInstaller(dest, out _))
            {
                (Current.MainWindow as MainWindow)?.PrepareForSilentRestart();
                Current.Shutdown();
            }
        }
        catch { /* non-fatal — the scheduled check will retry */ }
    }

    private static SemVer ResolveVersion()
    {
        var attr = Assembly.GetExecutingAssembly().GetName().Version;
        return attr is null ? new SemVer(0, 2, 0) : new SemVer(attr.Major, attr.Minor, attr.Build);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { Host?.Dispose(); } catch { /* best-effort */ }
        base.OnExit(e);
    }
}
