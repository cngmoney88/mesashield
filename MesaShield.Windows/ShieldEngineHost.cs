using System.Diagnostics;
using System.IO;
using System.Net.Http;
using MesaShield.Core;
using MesaShield.Core.Incidents;
using MesaShield.Core.Ml;
using MesaShield.Core.Net;
using MesaShield.Core.Privacy;

namespace MesaShield.Windows;

/// <summary>
/// The MesaShield protection engine, with no UI dependency. It owns every detection module
/// (real-time, process watch, behavior/ransomware guard, egress/DLP, deep ETW monitoring),
/// the on-device learners and offline models, the quarantine, the incident recorder, the
/// signature and app updaters, the scheduler, the fleet channel, and the self-defense watchdog.
///
/// It raises plain C# events and exposes command methods. The WPF app hosts it in-process and
/// marshals its events onto the UI thread; the Windows Service hosts it headless and forwards
/// its events over IPC. This is the single implementation of "what MesaShield does" — there is
/// no second copy to drift out of sync.
/// </summary>
public sealed class ShieldEngineHost : IDisposable
{
    // ---- Paths (all under the data root) --------------------------------
    public string DataDirectory { get; }
    public string SignaturesDirectory => Path.Combine(DataDirectory, "Signatures");
    public string RulesDirectory => Path.Combine(DataDirectory, "Rules");
    public string QuarantineDirectory => Path.Combine(DataDirectory, "Quarantine");
    public string LogsDirectory => Path.Combine(DataDirectory, "Logs");
    public string IncidentsDirectory => Path.Combine(DataDirectory, "Incidents");
    public string ReputationCachePath => Path.Combine(DataDirectory, "reputation-cache.json");
    public string StatusPathLocal => Path.Combine(DataDirectory, "status.json");
    public string AnomalyModelPath => Path.Combine(DataDirectory, "Models", "anomaly.json");
    public string NetworkModelPath => Path.Combine(DataDirectory, "Models", "network.json");
    public string BenignModelPath => Path.Combine(DataDirectory, "Models", "benign.json");
    public string ClassifierModelPath => Path.Combine(DataDirectory, "Models", "classifier.json");
    public string EgressStatePath => Path.Combine(DataDirectory, "Models", "egress.json");
    public string PrivacyAuditPath => Path.Combine(LogsDirectory, "network-audit.jsonl");

    // ---- Identity -------------------------------------------------------
    public SemVer Version { get; }
    public AppSettings Settings { get; }

    // ---- Components (constructed in InitializeAsync) --------------------
    public SignatureDatabase Signatures { get; } = new();
    public PatternScanner Patterns { get; } = new();
    public ScanEngine Engine { get; private set; } = null!;
    public QuarantineManager Quarantine { get; private set; } = null!;
    public ShieldEventLog EventLog { get; private set; } = null!;
    public IncidentStore Incidents { get; private set; } = null!;
    public SignatureUpdater Updater { get; private set; } = null!;
    public UpdateChecker AppUpdater { get; private set; } = null!;
    public ReputationClient Reputation { get; private set; } = null!;
    public AmsiScanner Amsi { get; private set; } = null!;
    public RealTimeProtector RealTime { get; private set; } = null!;
    public ProcessWatcher ProcessWatch { get; private set; } = null!;
    public UsbWatcher Usb { get; private set; } = null!;
    public FirewallManager Firewall { get; private set; } = null!;
    public BehaviorEngine Behavior { get; } = new();
    public BehaviorMonitor BehaviorWatch { get; private set; } = null!;
    public JobScheduler Scheduler { get; private set; } = null!;
    public AnomalyLearner Learner { get; private set; } = null!;
    public NetworkAnomalyLearner NetworkLearner { get; private set; } = null!;
    public EgressGuard Egress { get; private set; } = null!;
    public EgressWatcher EgressWatch { get; private set; } = null!;
    public MalwareClassifier? Classifier { get; private set; }
    public BenignAnomalyModel? BenignModel { get; private set; }
    public EtwMonitor Etw { get; private set; } = null!;
    public FleetReporter Fleet { get; private set; } = null!;

    public PrivacyGuard Privacy { get; } = new();
    public long ThreatsHandledTotal;

    /// <summary>True when another MesaShield engine (the always-on service) already owns protection
    /// on this machine. In passive mode the host constructs its modules but starts nothing — the app
    /// becomes a viewer and never double-runs the watchers, ETW session, scheduler, or fleet writes.</summary>
    public bool IsPassive { get; private set; }

    private readonly HttpClient _http;
    private System.Threading.Timer? _fleetTimer;
    private System.Threading.Timer? _fleetCommandTimer;
    private CancellationTokenSource? _selfDefenseCts;
    private int _learnerObservationsSinceSave;
    private bool _started;

    // ---- Events (UI-agnostic) ------------------------------------------
    public event Action<ThreatFinding, bool>? ThreatHandled;
    public event Action<ThreatFinding>? ProcessBlocked;
    public event Action<BehaviorAlert>? BehaviorAlert;
    public event Action<EgressDecision>? EgressDecision;
    public event Action<string>? UsbInserted;
    public event Action<string>? UsbRemoved;
    public event Action<ProcessObservation, AnomalyAssessment>? Anomaly;
    public event Action<AnomalyAssessment, string>? DeepAnomaly;
    public event Action<Incident>? IncidentRecorded;
    public event Action<string>? TamperHealed;
    public event Action? FirstRunStarted;
    public event Action<int>? FirstRunDone;
    public event Action<ScanSummary>? ScheduledScanDone;
    public event Action<ReleaseInfo>? UpdateAvailable;
    /// <summary>A verified, newer installer is downloaded and ready. Consumer decides how to apply it
    /// (the app relaunches; the service stops itself and lets the installer swap files).</summary>
    public event Action<string, string>? UpdateReadyToInstall;
    /// <summary>Best-effort audit sink for every outbound network decision.</summary>
    public event Action<NetworkAuditEntry>? NetworkDecision;

    public ShieldEngineHost(string dataDirectory, SemVer version, AppSettings settings)
    {
        DataDirectory = dataDirectory;
        Version = version;
        Settings = settings;
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(LogsDirectory);
        Privacy.Mode = settings.PrivacyMode;
        _http = new HttpClient(new PrivacyHandler(Privacy, new HttpClientHandler()))
        {
            Timeout = TimeSpan.FromMinutes(10),
            DefaultRequestHeaders = { { "User-Agent", "MesaShield" } },
        };
    }

    /// <summary>Construct and start every module, apply settings toggles, and begin background work.
    /// When <paramref name="passive"/> is true the modules are constructed but nothing is started —
    /// used by the desktop app when the always-on service already owns protection.</summary>
    public async Task InitializeAsync(bool passive = false)
    {
        IsPassive = passive;
        EventLog = new ShieldEventLog(LogsDirectory);
        Privacy.Decision += entry =>
        {
            NetworkDecision?.Invoke(entry);
            try { File.AppendAllText(PrivacyAuditPath, System.Text.Json.JsonSerializer.Serialize(entry) + Environment.NewLine); }
            catch { /* audit logging is best-effort */ }
        };
        try { EventLog.PurgeOlderThan(Settings.LogRetentionDays); } catch { }

        Quarantine = new QuarantineManager(QuarantineDirectory);
        Incidents = new IncidentStore(IncidentsDirectory);
        Updater = new SignatureUpdater(_http, SignaturesDirectory);
        AppUpdater = new UpdateChecker(_http);
        Reputation = new ReputationClient(_http,
            Settings.CloudLookupEnabled ? Settings.VirusTotalApiKey : null,
            Settings.CloudMaliciousThreshold, ReputationCachePath);
        Amsi = new AmsiScanner();

        Patterns.LoadBuiltInRules();
        Patterns.LoadRulesDirectory(RulesDirectory);
        await Signatures.LoadAsync(SignaturesDirectory);

        Learner = AnomalyLearner.Load(AnomalyModelPath);
        NetworkLearner = NetworkAnomalyLearner.Load(NetworkModelPath);
        Classifier = MalwareClassifier.Load(ClassifierModelPath) ?? MalwareClassifier.Baseline();
        BenignModel = BenignAnomalyModel.Load(BenignModelPath);

        Engine = new ScanEngine(Signatures, Patterns, new HeuristicAnalyzer())
        {
            ScriptScanner = Settings.AmsiScriptScanningEnabled ? Amsi : null,
            Reputation = Settings.CloudLookupEnabled ? Reputation : null,
            Classifier = Settings.MlClassifierEnabled ? Classifier : null,
            BenignModel = Settings.MlClassifierEnabled ? BenignModel : null,
        };

        var realTimeOptions = Settings.ToScanOptions();
        realTimeOptions.ExcludedPaths.Add(DataDirectory);
        RealTime = new RealTimeProtector(Engine, Quarantine, EventLog, realTimeOptions);
        ProcessWatch = new ProcessWatcher(Engine, Quarantine, EventLog);
        Usb = new UsbWatcher(EventLog);
        Firewall = new FirewallManager(EventLog);
        BehaviorWatch = new BehaviorMonitor(Behavior, EventLog);

        Egress = new EgressGuard(NetworkLearner) { Mode = Settings.EgressMode };
        Egress.Load(EgressStatePath);
        Egress.Mode = Settings.EgressMode;
        EgressWatch = new EgressWatcher(Egress, Firewall, EventLog);

        // ---- Wire module events to our own (and record incidents) ----
        RealTime.ThreatHandled += (finding, quarantined) =>
        {
            ThreatsHandledTotal++;
            ThreatHandled?.Invoke(finding, quarantined);
            _ = RecordIncidentAsync(quarantined ? "quarantine" : "detection",
                $"{finding.ThreatName} detected in {FileNameOf(finding.FilePath)}", finding.FilePath, finding.ThreatName);
        };
        ProcessWatch.ProcessBlocked += (_sender, finding) =>
        {
            ThreatsHandledTotal++;
            ProcessBlocked?.Invoke(finding);
            _ = RecordIncidentAsync("blocked", $"Program blocked: {finding.ThreatName}", finding.FilePath, finding.ThreatName);
        };
        BehaviorWatch.AlertRaised += alert =>
        {
            ThreatsHandledTotal++;
            BehaviorAlert?.Invoke(alert);
            _ = RecordIncidentAsync("behavior", alert.Message, null,
                alert.Severity == ThreatSeverity.Malicious ? "Behavior.Ransomware" : null);
        };
        EgressWatch.Decision += d => EgressDecision?.Invoke(d);
        Usb.DriveInserted += root =>
        {
            if (Settings.UsbAutoScanEnabled) RealTime.AddWatch(root);
            UsbInserted?.Invoke(root);
        };
        Usb.DriveRemoved += root => { RealTime.RemoveWatch(root); UsbRemoved?.Invoke(root); };
        ProcessWatch.ProcessObserved += obs =>
        {
            if (!Settings.AdaptiveLearningEnabled) return;
            var assessment = Learner.Observe(obs);
            if (++_learnerObservationsSinceSave >= 25)
            {
                _learnerObservationsSinceSave = 0;
                try { Learner.Save(AnomalyModelPath); } catch { }
            }
            if (!assessment.IsLearning && assessment.SuggestedSeverity is { } severity)
            {
                _ = EventLog.LogAsync(
                    severity == ThreatSeverity.Malicious ? "anomaly" : "detection",
                    $"Unusual for this machine ({assessment.Score:P0}): {string.Join("; ", assessment.Reasons)}",
                    obs.ExecutablePath, "Anomaly.Behavioral");
                Anomaly?.Invoke(obs, assessment);
            }
        };

        Etw = new EtwMonitor(Learner, NetworkLearner, EventLog);
        Etw.AnomalyDetected += (assessment, context) =>
        {
            ThreatsHandledTotal++;
            DeepAnomaly?.Invoke(assessment, context);
        };

        // In passive/viewer mode we stop here: modules exist but nothing runs. The service owns
        // protection; this instance only observes and displays it.
        if (passive)
        {
            _started = true;
            await EventLog.LogAsync("app", "MesaShield opened as a viewer — the always-on service is protecting this PC.");
            return;
        }

        // ---- Apply protection toggles ----
        if (Settings.RealTimeProtectionEnabled) RealTime.Start();
        if (Settings.ProcessMonitoringEnabled) ProcessWatch.Start();
        if (Settings.UsbAutoScanEnabled) Usb.Start();
        if (Settings.BehaviorGuardEnabled) BehaviorWatch.Start();
        if (Settings.EgressMode != EgressMode.Off) EgressWatch.Start();

        if (Settings.EtwMonitoringEnabled) Etw.Start();

        // If elevated, make deep monitoring permanent (relaunch elevated at logon, no prompts).
        if (ElevationManager.IsElevated)
        {
            try
            {
                var exe = Environment.ProcessPath;
                if (exe is not null && !ElevationManager.ElevatedAutostartExists())
                {
                    ElevationManager.InstallElevatedAutostart(exe);
                    await EventLog.LogAsync("etw", "Deep monitoring enabled permanently — MesaShield will run elevated at every logon.");
                }
            }
            catch { /* non-fatal */ }
        }

        Fleet = new FleetReporter(StatusPathLocal, BuildStatus)
        {
            SharedFolder = Settings.FleetReportingEnabled && !string.IsNullOrWhiteSpace(Settings.FleetSharedFolder)
                ? Settings.FleetSharedFolder : null,
        };
        try { Fleet.Report(); } catch { }
        _fleetTimer = new System.Threading.Timer(_ => { try { Fleet.Report(); } catch { } },
            null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        _fleetCommandTimer = new System.Threading.Timer(_ => { try { ProcessFleetCommands(); } catch { } },
            null, TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(45));

        Scheduler = new JobScheduler(Settings,
            onSignatureUpdate: RunSignatureUpdateAsync,
            onScheduledScan: RunScheduledScanAsync,
            onUpdateCheck: RunUpdateCheckAsync);
        Scheduler.Start();
        StartSelfDefense();
        _started = true;

        await EventLog.LogAsync("app", $"MesaShield engine {Version} started.");

        if (!Settings.FirstRunCompleted && Signatures.Count == 0)
            _ = FirstRunSetupAsync();
    }

    // ---- Status ---------------------------------------------------------
    public MachineStatus BuildStatus()
    {
        int quarantined = 0;
        try { quarantined = Quarantine.ListAsync().GetAwaiter().GetResult().Count; } catch { }
        long recentAlerts = 0;
        try
        {
            var since = DateTimeOffset.UtcNow.AddDays(-1);
            recentAlerts = EventLog.ReadRecentAsync(500).GetAwaiter().GetResult()
                .Count(e => e.Timestamp >= since && e.Kind is "blocked" or "quarantine" or "anomaly" or "detection");
        }
        catch { }

        return new MachineStatus
        {
            MachineName = Environment.MachineName,
            Version = Version.ToString(),
            RealTimeProtection = RealTime.IsRunning,
            BehaviorGuard = BehaviorWatch.IsRunning,
            ProcessMonitoring = ProcessWatch.IsRunning,
            AdaptiveLearning = Settings.AdaptiveLearningEnabled,
            SignatureCount = Signatures.Count,
            SignaturesUpdatedUtc = Signatures.LastUpdatedUtc,
            ThreatsHandled = ThreatsHandledTotal,
            InQuarantine = quarantined,
            RecentAlerts24h = recentAlerts,
            LearnerLearning = Learner.IsLearning,
            LearnerObservations = Learner.Observations,
            DeepMonitoring = Etw?.IsRunning ?? false,
            Elevated = ElevationManager.IsElevated,
            EgressMode = Settings.EgressMode.ToString(),
            PrivacyMode = Settings.PrivacyMode.ToString(),
            EgressBlocks24h = EgressBlocks24hCount(),
        };
    }

    private long EgressBlocks24hCount()
    {
        try
        {
            var since = DateTimeOffset.UtcNow.AddDays(-1);
            return EventLog.ReadRecentAsync(500).GetAwaiter().GetResult()
                .Count(e => e.Timestamp >= since && e.Kind == "egress" && e.Message.StartsWith("BLOCK", StringComparison.OrdinalIgnoreCase));
        }
        catch { return 0; }
    }

    // ---- Incident recording --------------------------------------------
    public async Task RecordIncidentAsync(string kind, string message, string? file, string? threat)
    {
        try
        {
            var trigger = new ShieldEventLog.ShieldEvent(DateTimeOffset.UtcNow, kind, message, file, threat);
            var recent = await EventLog.ReadRecentAsync(300);
            var incident = IncidentBuilder.Build(trigger, recent, TimeSpan.FromMinutes(10));
            Incidents.Save(incident);
            IncidentRecorded?.Invoke(incident);
        }
        catch (Exception ex) { try { await EventLog.LogAsync("error", $"Incident recording failed: {ex.Message}"); } catch { } }
    }

    // ---- Commands -------------------------------------------------------
    public void SetEgressMode(EgressMode mode)
    {
        Settings.EgressMode = mode;
        Egress.Mode = mode;
        Settings.Save();
        if (mode != EgressMode.Off && !EgressWatch.IsRunning) EgressWatch.Start();
    }

    public void SetPrivacyMode(PrivacyMode mode)
    {
        Settings.PrivacyMode = mode;
        Privacy.Mode = mode;
        Settings.Save();
    }

    public void ReloadBenignModel()
    {
        BenignModel = BenignAnomalyModel.Load(BenignModelPath);
        if (Engine is not null) Engine.BenignModel = Settings.MlClassifierEnabled ? BenignModel : null;
    }

    public string[] QuickScanTargets()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
        }.Where(Directory.Exists).ToArray();
    }

    public Task RunQuickScanAsync() => RunScanAsync(QuickScanTargets(), ScheduledScanScope.QuickScan);
    public Task RunFullScanAsync() => RunScanAsync(
        DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed)
            .Select(d => d.RootDirectory.FullName).ToArray(), ScheduledScanScope.FullScan);

    private async Task RunScanAsync(string[] targets, ScheduledScanScope scope)
    {
        var options = Settings.ToScanOptions();
        options.ExcludedPaths.Add(DataDirectory);
        var summary = await Engine.ScanAsync(targets, options,
            onResult: async result =>
            {
                foreach (var finding in result.Findings.Where(f => f.Severity == ThreatSeverity.Malicious))
                    await Quarantine.QuarantineAsync(finding);
            });
        await EventLog.LogAsync("scan", $"{scope} scanned {summary.FilesScanned:N0} files, {summary.Findings.Count} finding(s).");
        ScheduledScanDone?.Invoke(summary);
    }

    private Task RunScheduledScanAsync() =>
        Settings.ScheduledScanScope == ScheduledScanScope.FullScan ? RunFullScanAsync() : RunQuickScanAsync();

    public async Task RunSignatureUpdateAsync()
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(Settings.LocalSignatureMirror))
            {
                var installed = Updater.InstallFromLocalMirror(Settings.LocalSignatureMirror);
                await Signatures.LoadAsync(SignaturesDirectory);
                await EventLog.LogAsync("update", $"Signatures updated from local mirror ({installed} file(s)).");
                return;
            }
            if (Settings.PrivacyMode == PrivacyMode.Offline)
            {
                await EventLog.LogAsync("update", "Offline mode: skipped internet signature update (set a local mirror to update).");
                return;
            }
            await Updater.DownloadRecentAsync();
            await Signatures.LoadAsync(SignaturesDirectory);
            await EventLog.LogAsync("update", "Scheduled signature update completed.");
        }
        catch (Exception ex) { await EventLog.LogAsync("error", $"Scheduled signature update failed: {ex.Message}"); }
    }

    public async Task RunUpdateCheckAsync()
    {
        if (string.IsNullOrWhiteSpace(Settings.UpdateChannel) || !Settings.AutoUpdateEnabled) return;
        var result = await AppUpdater.CheckAsync(Settings.UpdateChannel, Version);
        if (!result.UpdateAvailable) return;

        var release = result.Release!;
        await EventLog.LogAsync("update", $"App update available: v{release.Version}.");

        if (Settings.AutoInstallUpdates)
        {
            var dest = await PrepareUpdateAsync(release);
            if (dest is not null) UpdateReadyToInstall?.Invoke(dest, release.Version.TrimStart('v', 'V'));
        }
        else
        {
            UpdateAvailable?.Invoke(release);
        }
    }

    /// <summary>Download, verify, downgrade-guard, and de-quarantine an update installer. Returns the
    /// path if it is ready to run, or null if it should be skipped.</summary>
    public async Task<string?> PrepareUpdateAsync(ReleaseInfo release)
    {
        try
        {
            var dir = Path.Combine(DataDirectory, "Updates");
            Directory.CreateDirectory(dir);
            var fileName = Path.GetFileName(new Uri(release.DownloadUrl).LocalPath);
            if (string.IsNullOrEmpty(fileName)) fileName = "MesaShield-Setup.exe";
            var dest = Path.Combine(dir, fileName);

            await AppUpdater.DownloadAsync(release, dest);   // verifies SHA-256 from the manifest

            try
            {
                var info = FileVersionInfo.GetVersionInfo(dest);
                var dv = new Version(info.FileMajorPart, info.FileMinorPart, info.FileBuildPart);
                var cur = new Version(Version.Major, Version.Minor, Version.Patch);
                if (dv <= cur) { await EventLog.LogAsync("update", $"Skipped auto-install: served v{dv} is not newer than v{cur}."); return null; }
            }
            catch { }

            MarkOfTheWeb.Remove(dest);   // after the hash check, so no SmartScreen prompt
            await EventLog.LogAsync("update", $"Update v{release.Version} downloaded and verified.");
            return dest;
        }
        catch (Exception ex)
        {
            await EventLog.LogAsync("error", $"Preparing update failed: {ex.Message}");
            return null;
        }
    }

    private async Task FirstRunSetupAsync()
    {
        try
        {
            FirstRunStarted?.Invoke();
            await Updater.DownloadFullDatabaseAsync();
            await Signatures.LoadAsync(SignaturesDirectory);
            Settings.FirstRunCompleted = true;
            Settings.Save();
            await EventLog.LogAsync("update", $"First-run setup complete: {Signatures.Count:N0} signatures installed.");
            FirstRunDone?.Invoke(Signatures.Count);
        }
        catch (Exception ex)
        {
            await EventLog.LogAsync("error", $"First-run signature download failed (will retry on schedule): {ex.Message}");
        }
    }

    // ---- Fleet command channel -----------------------------------------
    public void ProcessFleetCommands()
    {
        var shared = Settings.FleetSharedFolder;
        if (string.IsNullOrWhiteSpace(shared) || !Settings.FleetReportingEnabled) return;
        var me = Environment.MachineName;

        foreach (var cmd in FleetCommander.Pending(shared, me))
        {
            try
            {
                switch (cmd.Type)
                {
                    case FleetCommandType.QuickScan: _ = RunQuickScanAsync(); break;
                    case FleetCommandType.FullScan: _ = RunFullScanAsync(); break;
                    case FleetCommandType.UpdateSignatures: _ = RunSignatureUpdateAsync(); break;
                    case FleetCommandType.CheckAppUpdate: _ = RunUpdateCheckAsync(); break;
                    case FleetCommandType.SetPrivacyMode:
                        if (Enum.TryParse<PrivacyMode>(cmd.Arg, out var pm)) SetPrivacyMode(pm); break;
                    case FleetCommandType.SetEgressMode:
                        if (Enum.TryParse<EgressMode>(cmd.Arg, out var em)) SetEgressMode(em); break;
                    case FleetCommandType.Ping: break;
                }
                _ = EventLog.LogAsync("fleet", $"Ran fleet command {cmd.Type} (from {cmd.IssuedBy}).");
            }
            catch (Exception ex) { _ = EventLog.LogAsync("error", $"Fleet command {cmd.Type} failed: {ex.Message}"); }
            finally { FleetCommander.Ack(shared, cmd.Id, me); }
        }

        try { FleetCommander.Cleanup(shared, TimeSpan.FromDays(7)); } catch { }
        try { Fleet.Report(); } catch { }
    }

    // ---- Self-defense watchdog -----------------------------------------
    private void StartSelfDefense()
    {
        _selfDefenseCts = new CancellationTokenSource();
        var ct = _selfDefenseCts.Token;
        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), ct);

                    void Heal(string name, bool shouldRun, bool isRunning, Action restart)
                    {
                        if (shouldRun && !isRunning)
                        {
                            restart();
                            _ = EventLog.LogAsync("tamper", $"Protection module '{name}' was not running and has been restarted.");
                            TamperHealed?.Invoke(name);
                        }
                    }

                    Heal("Real-time protection", Settings.RealTimeProtectionEnabled, RealTime.IsRunning, () => RealTime.Start());
                    Heal("Process monitoring", Settings.ProcessMonitoringEnabled, ProcessWatch.IsRunning, () => ProcessWatch.Start());
                    Heal("Ransomware guard", Settings.BehaviorGuardEnabled, BehaviorWatch.IsRunning, () => BehaviorWatch.Start());
                    Heal("Egress control", Settings.EgressMode != EgressMode.Off, EgressWatch.IsRunning, () => EgressWatch.Start());

                    if (ElevationManager.IsElevated && !ElevationManager.ElevatedAutostartExists())
                    {
                        var exe = Environment.ProcessPath;
                        if (exe is not null)
                        {
                            ElevationManager.InstallElevatedAutostart(exe);
                            _ = EventLog.LogAsync("tamper", "Elevated autostart was missing and has been re-registered.");
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { /* keep watching */ }
            }
        }, ct);
    }

    public void EraseAllLearnedData()
    {
        foreach (var f in new[] { AnomalyModelPath, NetworkModelPath, BenignModelPath })
            try { if (File.Exists(f)) File.Delete(f); } catch { }
        try { if (Directory.Exists(LogsDirectory)) foreach (var f in Directory.EnumerateFiles(LogsDirectory)) File.Delete(f); } catch { }
        Learner = AnomalyLearner.Load(AnomalyModelPath);
        NetworkLearner = NetworkAnomalyLearner.Load(NetworkModelPath);
        BenignModel = BenignAnomalyModel.Load(BenignModelPath);
        _ = EventLog.LogAsync("privacy", "All learned data and logs erased at user request.");
    }

    private static string FileNameOf(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        var idx = path.LastIndexOfAny(new[] { '\\', '/' });
        return idx >= 0 && idx < path.Length - 1 ? path[(idx + 1)..] : path;
    }

    public void Dispose()
    {
        if (!_started) return;
        try { _selfDefenseCts?.Cancel(); } catch { }
        try { Learner?.Save(AnomalyModelPath); } catch { }
        try { NetworkLearner?.Save(NetworkModelPath); } catch { }
        try { Egress?.Save(EgressStatePath); } catch { }
        _fleetTimer?.Dispose();
        _fleetCommandTimer?.Dispose();
        EgressWatch?.Dispose();
        Etw?.Dispose();
        Scheduler?.Dispose();
        RealTime?.Dispose();
        ProcessWatch?.Dispose();
        BehaviorWatch?.Dispose();
        Usb?.Dispose();
        Amsi?.Dispose();
        _http.Dispose();
    }
}
