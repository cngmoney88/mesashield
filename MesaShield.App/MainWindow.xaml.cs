using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using MesaShield.Core;
using MesaShield.Windows;
using MessageBox = System.Windows.MessageBox;
using Button = System.Windows.Controls.Button;

namespace MesaShield.App;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ThreatFinding> _findings = new();
    private readonly ObservableCollection<MesaShield.Core.Incidents.Incident> _incidents = new();
    private CancellationTokenSource? _scanCts;
    private long _threatsHandled;
    private TrayIcon? _tray;
    private ReleaseInfo? _pendingUpdate;
    private bool _reallyClosing;

    public MainWindow()
    {
        InitializeComponent();
        FindingsList.ItemsSource = _findings;
        Loaded += async (_, _) => await InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        while (App.Engine is null) await Task.Delay(50);

        VersionText.Text = $"MesaShield {App.CurrentVersion}";
        _tray = new TrayIcon();
        _tray.OpenRequested += ShowFromTray;
        _tray.QuickScanRequested += () => Dispatcher.Invoke(() => { ShowFromTray(); ShowPage("Scan"); QuickScan_Click(this, new RoutedEventArgs()); });
        _tray.ProtectionToggleRequested += enable => Dispatcher.Invoke(() => ToggleAllProtection(enable));
        _tray.QuitRequested += () => Dispatcher.Invoke(() => { _reallyClosing = true; Close(); });

        App.RealTime.ThreatHandled += (finding, quarantined) => Dispatcher.Invoke(() =>
        {
            _threatsHandled++;
            RefreshDashboardCounters();
            _ = RefreshActivityAsync();
            if (App.Settings.ShowNotifications)
                _tray?.Notify("Threat blocked", $"{finding.ThreatName}\n{Path.GetFileName(finding.FilePath)}", warning: true);
            _ = App.RecordIncidentAsync(quarantined ? "quarantine" : "detection",
                $"{finding.ThreatName} detected in {Path.GetFileName(finding.FilePath)}", finding.FilePath, finding.ThreatName);
        });
        App.ProcessWatch.ProcessBlocked += (_sender, finding) => Dispatcher.Invoke(() =>
        {
            _threatsHandled++;
            RefreshDashboardCounters();
            if (App.Settings.ShowNotifications)
                _tray?.Notify("Program blocked", finding.ThreatName, warning: true);
            _ = App.RecordIncidentAsync("blocked", $"Program blocked: {finding.ThreatName}", finding.FilePath, finding.ThreatName);
        });
        App.BehaviorWatch.AlertRaised += alert => Dispatcher.Invoke(() =>
        {
            _threatsHandled++;
            RefreshDashboardCounters();
            _ = RefreshActivityAsync();
            if (App.Settings.ShowNotifications)
                _tray?.Notify(alert.Severity == ThreatSeverity.Malicious ? "⚠ Ransomware blocked" : "Suspicious activity", alert.Message, warning: true);
            _ = App.RecordIncidentAsync("behavior", alert.Message, null, alert.Severity == ThreatSeverity.Malicious ? "Behavior.Ransomware" : null);
        });

        UpdateRealTimeCard();
        UpdateDeepMonitorPrompt();
        RefreshDashboardCounters();
        RefreshSignatureCard();
        await RefreshActivityAsync();
        await RefreshQuarantineAsync();
        LoadSettingsIntoUi();

        if (App.Signatures.Count == 0)
            UpdateStatusText.Text = "No signature database installed yet — open Settings to download it. " +
                                    "Pattern and heuristic detection work without it.";

        if (App.StartMinimized && App.Settings.StartMinimizedToTray)
            Hide();
    }

    public void OnUsbInserted(string root)
    {
        var answer = MessageBox.Show(
            $"Removable drive {root} was plugged in and is now being watched.\n\nRun a full scan of it now?",
            "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer == MessageBoxResult.Yes)
        {
            ShowPage("Scan");
            _ = RunScanAsync(new[] { root }, $"Scanning {root}");
        }
    }

    /// <summary>A detection was reconstructed into a full incident story — surface it and keep the last few.</summary>
    public void OnIncident(MesaShield.Core.Incidents.Incident incident)
    {
        _incidents.Insert(0, incident);
        while (_incidents.Count > 50) _incidents.RemoveAt(_incidents.Count - 1);
        if (App.Settings.ShowNotifications)
            _tray?.Notify(
                incident.Severity == ThreatSeverity.Malicious ? "⚠ Incident contained" : "Incident recorded",
                incident.Title,
                warning: incident.Severity == ThreatSeverity.Malicious);
        _ = RefreshActivityAsync();
    }

    // ---- Notifications from background jobs -------------------------------

    public void NotifyFirstRunStarted()
    {
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Setting up MesaShield", "Downloading the malware signature database in the background…");
        UpdateStatusText.Text = "First-time setup: downloading the full signature database…";
    }

    public void NotifyFirstRunDone(int count)
    {
        RefreshSignatureCard();
        UpdateStatusText.Text = $"Setup complete — {count:N0} signatures installed. Protection is fully active.";
        if (App.Settings.ShowNotifications)
            _tray?.Notify("MesaShield is ready", $"{count:N0} malware signatures installed. You're protected.");
    }

    public void NotifyTamper(string moduleName)
    {
        if (App.Settings.ShowNotifications)
            _tray?.Notify("⚠ Protection restored", $"{moduleName} had been stopped — MesaShield restarted it automatically.", warning: true);
        _ = RefreshActivityAsync();
    }

    public void NotifyAnomaly(MesaShield.Core.Ml.ProcessObservation obs, MesaShield.Core.Ml.AnomalyAssessment assessment)
    {
        _threatsHandled++;
        RefreshDashboardCounters();
        _ = RefreshActivityAsync();
        if (App.Settings.ShowNotifications)
            _tray?.Notify(
                assessment.SuggestedSeverity == ThreatSeverity.Malicious ? "⚠ Unusual activity blocked-worthy" : "Unusual activity",
                $"{System.IO.Path.GetFileName(obs.ExecutablePath)} — {string.Join("; ", assessment.Reasons)}",
                warning: true);
    }

    public void NotifyDeepAnomaly(MesaShield.Core.Ml.AnomalyAssessment assessment, string context)
    {
        _threatsHandled++;
        RefreshDashboardCounters();
        _ = RefreshActivityAsync();
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Unusual activity (deep monitor)",
                $"{context} — {string.Join("; ", assessment.Reasons)}", warning: true);
    }

    public void NotifyScheduledScanDone(ScanSummary summary)
    {
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Scheduled scan complete",
                $"{summary.FilesScanned:N0} files scanned, {summary.Findings.Count} finding(s).");
        RefreshDashboardCounters();
    }

    public void NotifyUpdateAvailable(ReleaseInfo release)
    {
        _pendingUpdate = release;
        var v = release.Version.TrimStart('v', 'V');   // tags come as "v0.10.0"; don't render "vv0.10.0"
        UpdateBannerText.Text = $"MesaShield v{v} is available." +
                                (string.IsNullOrWhiteSpace(release.Notes) ? "" : $" {release.Notes}");
        UpdateBanner.Visibility = Visibility.Visible;
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Update available", $"MesaShield v{v} is ready to install.");
    }

    // ---- Tray / minimize-to-tray -----------------------------------------

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    /// <summary>Allow a real shutdown (not hide-to-tray) so a silent auto-update can relaunch us.</summary>
    public void PrepareForSilentRestart() => _reallyClosing = true;

    /// <summary>Bring the single window to the foreground (called when a second launch is attempted).</summary>
    public void BringToFront()
    {
        Show();
        WindowState = WindowState.Normal;
        Topmost = true;
        Activate();
        Topmost = false;
        Focus();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (WindowState == WindowState.Minimized && App.Settings.StartMinimizedToTray)
            Hide();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Closing the window just hides to tray; real exit comes from the tray menu.
        if (!_reallyClosing)
        {
            e.Cancel = true;
            Hide();
            _tray?.Notify("Still protecting you", "MesaShield is running in the background. Right-click the tray icon to quit.");
            return;
        }
        _tray?.Dispose();
        base.OnClosing(e);
    }

    private void ToggleAllProtection(bool enable)
    {
        if (enable)
        {
            if (App.Settings.RealTimeProtectionEnabled) App.RealTime.Start();
            if (App.Settings.ProcessMonitoringEnabled) App.ProcessWatch.Start();
            if (App.Settings.BehaviorGuardEnabled) App.BehaviorWatch.Start();
        }
        else
        {
            App.RealTime.Stop();
            App.ProcessWatch.Dispose();
            App.BehaviorWatch.Stop();
        }
        _tray?.SetStatus(enable);
        UpdateRealTimeCard();
    }

    // ---- Navigation -------------------------------------------------------

    private void Nav_Click(object sender, RoutedEventArgs e) => ShowPage((string)((Button)sender).Tag);

    private void ShowPage(string page)
    {
        PageDashboard.Visibility = page == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        PageScan.Visibility = page == "Scan" ? Visibility.Visible : Visibility.Collapsed;
        PageQuarantine.Visibility = page == "Quarantine" ? Visibility.Visible : Visibility.Collapsed;
        PageFirewall.Visibility = page == "Firewall" ? Visibility.Visible : Visibility.Collapsed;
        PageActivity.Visibility = page == "Activity" ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = page == "Settings" ? Visibility.Visible : Visibility.Collapsed;
        PagePrivacy.Visibility = page == "Privacy" ? Visibility.Visible : Visibility.Collapsed;
        PageTraffic.Visibility = page == "Traffic" ? Visibility.Visible : Visibility.Collapsed;
        if (page == "Privacy") LoadPrivacyPage();
        if (page == "Traffic") LoadTrafficPage();
        PageFleet.Visibility = page == "Fleet" ? Visibility.Visible : Visibility.Collapsed;

        if (page == "Quarantine") _ = RefreshQuarantineAsync();
        if (page == "Activity") _ = RefreshActivityAsync();
        if (page == "Firewall") RefreshConnections();
        if (page == "Fleet") RefreshFleet();
        if (page == "Dashboard") { RefreshDashboardCounters(); _ = RefreshActivityAsync(); }
    }

    // ---- Dashboard --------------------------------------------------------

    private void UpdateDeepMonitorPrompt()
    {
        // Show the "enable" button only when deep monitoring isn't already running (i.e. not elevated yet).
        EnableDeepMonitorButton.Visibility = App.Etw.IsRunning ? Visibility.Collapsed : Visibility.Visible;
    }

    private void EnableDeepMonitor_Click(object sender, RoutedEventArgs e)
    {
        if (ElevationManager.IsElevated)
        {
            // Already elevated but ETW not running — just start it.
            App.Etw.Start();
            UpdateDeepMonitorPrompt();
            MessageBox.Show(App.Etw.IsRunning ? "Deep monitoring is on." : $"Couldn't start deep monitoring: {App.Etw.Status}",
                "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var answer = MessageBox.Show(
            "Deep monitoring reads Windows' low-level event stream, which needs administrator rights.\n\n" +
            "MesaShield will ask for permission once (a Windows UAC prompt), then set itself to run with " +
            "those rights automatically at every startup — no more prompts.\n\nContinue?",
            "Enable deep monitoring", MessageBoxButton.YesNo, MessageBoxImage.Information);
        if (answer != MessageBoxResult.Yes) return;

        if (ElevationManager.RelaunchAsAdmin("--minimized"))
        {
            // The elevated instance takes over (and sets up permanent elevated autostart); close this one.
            _reallyClosing = true;
            System.Windows.Application.Current.Shutdown();
        }
        else
        {
            MessageBox.Show("Elevation was cancelled. Deep monitoring stays off; everything else keeps working.",
                "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void UpdateRealTimeCard()
    {
        var on = App.RealTime.IsRunning;
        RealTimeStatus.Text = on ? "On" : "Off";
        RealTimeStatus.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GoodBrush" : "BadBrush");
        RealTimeToggle.Content = on ? "Turn off" : "Turn on";
    }

    private void RealTimeToggle_Click(object sender, RoutedEventArgs e)
    {
        if (App.RealTime.IsRunning) App.RealTime.Stop();
        else App.RealTime.Start();
        UpdateRealTimeCard();
    }

    private async void RefreshDashboardCounters()
    {
        ThreatCount.Text = _threatsHandled.ToString("N0");
        App.ThreatsHandledTotal = _threatsHandled;
        var entries = await App.Quarantine.ListAsync();
        QuarantineCount.Text = $"{entries.Count} in quarantine";
    }

    private void RefreshSignatureCard()
    {
        SignatureCount.Text = App.Signatures.Count.ToString("N0");
        SignatureUpdated.Text = App.Signatures.LastUpdatedUtc is { } updated
            ? $"Updated {updated.ToLocalTime():g}" : "Never updated";
    }

    // ---- Scan -------------------------------------------------------------

    private void QuickScan_Click(object sender, RoutedEventArgs e) =>
        _ = RunScanAsync(App.QuickScanTargets(), "Quick scan");

    private void FullScan_Click(object sender, RoutedEventArgs e)
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable)
            .Select(d => d.RootDirectory.FullName).ToArray();
        _ = RunScanAsync(drives, "Full scan");
    }

    private void CustomScan_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Choose a folder to scan" };
        if (dialog.ShowDialog() == true)
            _ = RunScanAsync(new[] { dialog.FolderName }, $"Scanning {dialog.FolderName}");
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e) => _scanCts?.Cancel();

    private async Task RunScanAsync(string[] targets, string label)
    {
        if (_scanCts is not null) return;
        _scanCts = new CancellationTokenSource();
        _findings.Clear();
        SetScanUi(true, $"{label} — starting...");

        var options = App.Settings.ToScanOptions();
        options.ExcludedPaths.Add(App.DataDirectory);

        var progress = new Progress<ScanProgress>(p =>
        {
            ScanStatusText.Text = $"{label} — {p.FilesScanned:N0} files scanned, {p.ThreatsFound} finding(s)";
            ScanCurrentFile.Text = p.CurrentFile;
        });

        try
        {
            var summary = await App.Engine.ScanAsync(targets, options, progress,
                onResult: result =>
                {
                    foreach (var finding in result.Findings)
                        Dispatcher.Invoke(() => _findings.Add(finding));
                    return Task.CompletedTask;
                }, ct: _scanCts.Token);

            var duration = (summary.FinishedAt!.Value - summary.StartedAt).TotalMinutes;
            ScanStatusText.Text = summary.WasCancelled
                ? $"{label} cancelled after {summary.FilesScanned:N0} files."
                : $"{label} complete: {summary.FilesScanned:N0} files ({summary.BytesScanned / (1024.0 * 1024 * 1024):F1} GB) in {duration:F1} min — {summary.Findings.Count} finding(s).";
            await App.EventLog.LogAsync("scan", ScanStatusText.Text);
        }
        catch (Exception ex)
        {
            ScanStatusText.Text = $"Scan failed: {ex.Message}";
        }
        finally
        {
            _scanCts.Dispose();
            _scanCts = null;
            SetScanUi(false, ScanStatusText.Text);
        }
    }

    private void SetScanUi(bool scanning, string status)
    {
        ScanStatusText.Text = status;
        ScanProgressBar.IsIndeterminate = scanning;
        CancelScanButton.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
        QuickScanButton.IsEnabled = FullScanButton.IsEnabled = CustomScanButton.IsEnabled = !scanning;
        if (!scanning) ScanCurrentFile.Text = "";
    }

    private async void QuarantineSelected_Click(object sender, RoutedEventArgs e) =>
        await QuarantineFindingsAsync(FindingsList.SelectedItems.Cast<ThreatFinding>().ToList());

    private async void QuarantineAll_Click(object sender, RoutedEventArgs e) =>
        await QuarantineFindingsAsync(_findings.Where(f => f.Severity == ThreatSeverity.Malicious).ToList());

    private async Task QuarantineFindingsAsync(List<ThreatFinding> findings)
    {
        var done = 0;
        foreach (var finding in findings)
        {
            var entry = await App.Quarantine.QuarantineAsync(finding);
            if (entry is not null)
            {
                done++; _threatsHandled++;
                _findings.Remove(finding);
                await App.EventLog.LogAsync("quarantine", $"Quarantined {finding.ThreatName}", finding.FilePath, finding.ThreatName);
            }
        }
        RefreshDashboardCounters();
        if (done > 0)
            MessageBox.Show($"{done} file(s) moved to quarantine.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ---- Quarantine -------------------------------------------------------

    private sealed record QuarantineRow(string Id, string When, string ThreatName, string OriginalPath, string Size);

    private async Task RefreshQuarantineAsync()
    {
        var entries = await App.Quarantine.ListAsync();
        QuarantineList.ItemsSource = entries.OrderByDescending(q => q.QuarantinedAt)
            .Select(q => new QuarantineRow(q.Id, q.QuarantinedAt.ToLocalTime().ToString("g"), q.ThreatName, q.OriginalPath,
                q.OriginalSize < 1024 * 1024 ? $"{q.OriginalSize / 1024.0:F0} KB" : $"{q.OriginalSize / (1024.0 * 1024):F1} MB"))
            .ToList();
    }

    private async void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var rows = QuarantineList.SelectedItems.Cast<QuarantineRow>().ToList();
        if (rows.Count == 0) return;
        if (MessageBox.Show($"Restore {rows.Count} file(s)? Only do this if you're confident they were false positives.",
                "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var row in rows)
            if (await App.Quarantine.RestoreAsync(row.Id))
                await App.EventLog.LogAsync("restore", $"Restored from quarantine: {row.OriginalPath}", row.OriginalPath);
        await RefreshQuarantineAsync();
        RefreshDashboardCounters();
    }

    private async void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var rows = QuarantineList.SelectedItems.Cast<QuarantineRow>().ToList();
        if (rows.Count == 0) return;
        if (MessageBox.Show($"Permanently delete {rows.Count} file(s)? This cannot be undone.",
                "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var row in rows) await App.Quarantine.DeleteAsync(row.Id);
        await RefreshQuarantineAsync();
        RefreshDashboardCounters();
    }

    // ---- Firewall ---------------------------------------------------------

    private void RefreshConnections_Click(object sender, RoutedEventArgs e) => RefreshConnections();

    private void RefreshConnections()
    {
        try
        {
            ConnectionsList.ItemsSource = ConnectionMonitor.Snapshot();
            FirewallStateText.Text = App.Firewall.IsFirewallEnabled() ? "Windows Firewall: ON" : "⚠ Windows Firewall is OFF";
        }
        catch (Exception ex) { FirewallStateText.Text = $"Error: {ex.Message}"; }
    }

    private async void BlockApp_Click(object sender, RoutedEventArgs e)
    {
        if (ConnectionsList.SelectedItem is not ConnectionMonitor.ConnectionInfo c) return;
        if (c.ExecutablePath is null)
        {
            MessageBox.Show("Can't resolve that process's executable (protected system process).", "MesaShield");
            return;
        }
        try
        {
            await App.Firewall.BlockApplicationAsync(c.ExecutablePath, "Blocked by user.");
            MessageBox.Show($"Blocked {c.ProcessName}.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show("Firewall changes need administrator rights. Restart MesaShield as administrator.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void UnblockApp_Click(object sender, RoutedEventArgs e)
    {
        if (ConnectionsList.SelectedItem is not ConnectionMonitor.ConnectionInfo c || c.ExecutablePath is null) return;
        try
        {
            await App.Firewall.RemoveRulesForApplicationAsync(c.ExecutablePath);
            MessageBox.Show($"Removed MesaShield firewall rules for {c.ProcessName}.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show("Firewall changes need administrator rights.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // ---- Fleet ------------------------------------------------------------

    private sealed record FleetRow(string Machine, string Health, string Version, string Protection,
        string Signatures, string Alerts, string Quarantine, string Learning, string LastSeen);

    private void RefreshFleet_Click(object sender, RoutedEventArgs e) => RefreshFleet();

    private void RefreshFleet()
    {
        // Always publish our own latest status first so this machine appears current.
        try { App.Fleet.Report(); } catch { }

        var folder = App.Settings.FleetSharedFolder;
        if (string.IsNullOrWhiteSpace(folder))
        {
            FleetStatusText.Text = "No shared folder set. Add one in Settings (e.g. \\\\SERVER\\MesaShield\\status) so every machine's status shows here. Showing this machine only.";
            FleetList.ItemsSource = new[] { ToRow(BuildSelfStatus()) };
            return;
        }

        try
        {
            var machines = FleetReader.ReadAll(folder);
            if (machines.Count == 0)
            {
                FleetStatusText.Text = $"No machines have reported to {folder} yet. Install MesaShield on the other machines and point them at the same folder.";
                FleetList.ItemsSource = new[] { ToRow(BuildSelfStatus()) };
                return;
            }
            var atRisk = machines.Count(m => m.Health == "at-risk");
            var attention = machines.Count(m => m.Health == "attention");
            FleetStatusText.Text = $"{machines.Count} machine(s) — {machines.Count - atRisk - attention} protected, {attention} need attention, {atRisk} at risk.";
            FleetList.ItemsSource = machines.Select(ToRow).ToList();
        }
        catch (Exception ex)
        {
            FleetStatusText.Text = $"Can't read the shared folder: {ex.Message}";
        }
    }

    private static MachineStatus BuildSelfStatus()
    {
        try { return FleetReader.ReadAll(Path.GetDirectoryName(App.StatusPathLocal)!).FirstOrDefault() ?? Fallback(); }
        catch { return Fallback(); }

        static MachineStatus Fallback() => new() { MachineName = Environment.MachineName, Version = App.CurrentVersion.ToString(), RealTimeProtection = App.RealTime.IsRunning, SignatureCount = App.Signatures.Count };
    }

    private void FleetCmd_Click(object sender, RoutedEventArgs e)
    {
        var folder = App.Settings.FleetSharedFolder;
        if (string.IsNullOrWhiteSpace(folder))
        {
            MessageBox.Show("Set a shared fleet folder in Settings first (e.g. \\\\SERVER\\MesaShield).", "MesaShield");
            return;
        }

        // Target: the selected machine, or all machines if the box is ticked.
        string target;
        if (FleetToAll.IsChecked == true) target = "*";
        else if (FleetList.SelectedItem is FleetRow row) target = row.Machine.Replace(" (stale)", "");
        else { MessageBox.Show("Select a machine in the list, or tick \"Send to ALL machines.\"", "MesaShield"); return; }

        var tag = (string)((Button)sender).Tag;
        var parts = tag.Split(':');
        if (!Enum.TryParse<FleetCommandType>(parts[0], out var type)) return;
        var arg = parts.Length > 1 ? parts[1] : null;

        try
        {
            FleetCommander.Issue(folder, type, target, arg);
            MessageBox.Show($"Sent '{type}{(arg is null ? "" : " " + arg)}' to {(target == "*" ? "all machines" : target)}.\n\n" +
                            "Machines apply pushed commands within a minute.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show($"Couldn't send the command: {ex.Message}", "MesaShield"); }
    }

    private static FleetRow ToRow(MachineStatus s) => new(
        Machine: s.MachineName + (s.IsStale(TimeSpan.FromMinutes(30)) ? " (stale)" : ""),
        Health: s.Health switch { "protected" => "● Protected", "attention" => "▲ Attention", _ => "✖ At risk" },
        Version: s.Version,
        Protection: s.RealTimeProtection ? "On" : "OFF",
        Signatures: s.SignatureCount.ToString("N0"),
        Alerts: s.RecentAlerts24h.ToString(),
        Quarantine: s.InQuarantine.ToString(),
        Learning: s.LearnerLearning ? $"learning ({s.LearnerObservations})" : "active",
        LastSeen: s.ReportedUtc.ToLocalTime().ToString("g"));

    // ---- Activity ---------------------------------------------------------

    private sealed record ActivityRow(string Time, string Kind, string Message, string? FilePath);

    private void RefreshActivity_Click(object sender, RoutedEventArgs e) => _ = RefreshActivityAsync();

    private async Task RefreshActivityAsync()
    {
        var events = await App.EventLog.ReadRecentAsync(300);
        var rows = events.Select(evt => new ActivityRow(
            evt.Timestamp.ToLocalTime().ToString("g"), evt.Kind, evt.Message, evt.FilePath)).ToList();
        ActivityList.ItemsSource = rows;
        DashboardActivity.ItemsSource = rows.Take(12).ToList();
    }

    // ---- Signature updates ------------------------------------------------

    private async void FullUpdate_Click(object sender, RoutedEventArgs e) => await RunUpdateAsync(true);
    private async void QuickUpdate_Click(object sender, RoutedEventArgs e) => await RunUpdateAsync(false);

    private async Task RunUpdateAsync(bool full)
    {
        FullUpdateButton.IsEnabled = QuickUpdateButton.IsEnabled = false;
        var progress = new Progress<string>(m => UpdateStatusText.Text = m);
        try
        {
            var count = full ? await App.Updater.DownloadFullDatabaseAsync(progress)
                             : await App.Updater.DownloadRecentAsync(progress);
            await App.Signatures.LoadAsync(App.SignaturesDirectory);
            RefreshSignatureCard();
            UpdateStatusText.Text += $" Database now holds {App.Signatures.Count:N0} signatures.";
            await App.EventLog.LogAsync("update", $"Signature update ({(full ? "full" : "incremental")}): {count:N0} hashes.");
        }
        catch (Exception ex) { UpdateStatusText.Text = $"Update failed: {ex.Message}"; }
        finally { FullUpdateButton.IsEnabled = QuickUpdateButton.IsEnabled = true; }
    }

    // ---- App update banner ------------------------------------------------

    private async void CheckUpdate_Click(object sender, RoutedEventArgs e)
    {
        var channel = TxtUpdateChannel.Text.Trim();
        if (string.IsNullOrWhiteSpace(channel))
        {
            MessageBox.Show("Enter an update source first (a GitHub owner/repo or a manifest URL).", "MesaShield");
            return;
        }
        try
        {
            var result = await App.AppUpdater.CheckAsync(channel, App.CurrentVersion);
            if (result.UpdateAvailable) NotifyUpdateAvailable(result.Release!);
            else MessageBox.Show($"You're up to date (v{App.CurrentVersion}).", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show($"Update check failed: {ex.Message}", "MesaShield"); }
    }

    private async void DownloadUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdate is null) return;
        var version = _pendingUpdate.Version.TrimStart('v', 'V');
        var target = Path.Combine(App.DataDirectory, "Updates");
        Directory.CreateDirectory(target);
        var fileName = Path.GetFileName(new Uri(_pendingUpdate.DownloadUrl).LocalPath);
        if (string.IsNullOrEmpty(fileName)) fileName = "MesaShield-Setup.exe";
        var dest = Path.Combine(target, fileName);

        var downloadButton = sender as Button;
        try
        {
            if (downloadButton is not null) downloadButton.IsEnabled = false;
            UpdateBannerText.Text = $"Downloading v{version}… (this can take a minute)";
            await App.AppUpdater.DownloadAsync(_pendingUpdate, dest);

            // DOWNGRADE GUARD: never install an update that isn't actually newer than what's running
            // (protects against a stale release whose tag says "new" but whose binary is old).
            try
            {
                var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(dest);
                var dv = new Version(info.FileMajorPart, info.FileMinorPart, info.FileBuildPart);
                var cur = new Version(App.CurrentVersion.Major, App.CurrentVersion.Minor, App.CurrentVersion.Patch);
                if (dv <= cur)
                {
                    UpdateBanner.Visibility = Visibility.Collapsed;
                    MessageBox.Show($"The update source is serving v{dv}, which is not newer than your v{cur}. " +
                        "Skipping to avoid downgrading. (Your GitHub release may be out of date.)",
                        "MesaShield", MessageBoxButton.OK, MessageBoxImage.Warning);
                    if (downloadButton is not null) downloadButton.IsEnabled = true;
                    return;
                }
            }
            catch { /* if version can't be read, fall through — the installer has its own guard */ }

            // Strip the internet mark (after the verified download) so there's no SmartScreen prompt.
            MesaShield.Windows.MarkOfTheWeb.Remove(dest);

            await App.EventLog.LogAsync("update", $"Downloaded app update v{version}.");
            UpdateBannerText.Text = $"v{version} downloaded.";

            // Hand off to the downloaded self-installer once we exit. Because the installer isn't
            // code-signed yet, Windows may show a SmartScreen prompt — tell the user plainly so they
            // approve it, instead of the update seeming to do nothing.
            var proceed = MessageBox.Show(
                $"MesaShield v{version} is downloaded and ready to install.\n\n" +
                "MesaShield will close, install the update, and reopen.\n\n" +
                "If Windows shows a blue \"Windows protected your PC\" box, click \"More info\" then " +
                "\"Run anyway\" — that's just because the app isn't code-signed yet.\n\nInstall now?",
                "Install update", MessageBoxButton.YesNo, MessageBoxImage.Information);

            if (proceed != MessageBoxResult.Yes)
            {
                UpdateBannerText.Text = $"v{version} ready — click Update now when you're ready.";
                if (downloadButton is not null) downloadButton.IsEnabled = true;
                return;
            }

            if (SelfUpdater.LaunchInstaller(dest, out var message))
            {
                _reallyClosing = true;
                System.Windows.Application.Current.Shutdown();
            }
            else
            {
                // Couldn't hand off — give the user a direct way to finish it themselves.
                var open = MessageBox.Show(
                    $"Couldn't start the installer automatically ({message}).\n\n" +
                    $"The installer is here:\n{dest}\n\nOpen its folder so you can run it?",
                    "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (open == MessageBoxResult.Yes)
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"/select,\"{dest}\"") { UseShellExecute = true });
                if (downloadButton is not null) downloadButton.IsEnabled = true;
            }
        }
        catch (Exception ex)
        {
            UpdateBannerText.Text = $"Update download failed: {ex.Message}";
            if (downloadButton is not null) downloadButton.IsEnabled = true;
        }
    }

    private void DismissBanner_Click(object sender, RoutedEventArgs e) => UpdateBanner.Visibility = Visibility.Collapsed;

    // ---- Settings ---------------------------------------------------------

    // ---- Traffic / egress page -------------------------------------------

    private sealed class EgressRow
    {
        public string Time { get; init; } = "";
        public string Process { get; init; } = "";
        public string Destination { get; init; } = "";
        public string Action { get; init; } = "";
        public string Reason { get; init; } = "";
        public MesaShield.Core.Ml.NetworkObservation? Observation { get; init; }
    }

    private readonly ObservableCollection<EgressRow> _egressRows = new();

    private void LoadTrafficPage()
    {
        var mode = App.Settings.EgressMode;
        RbEgressOff.IsChecked = mode == MesaShield.Core.Net.EgressMode.Off;
        RbEgressObserve.IsChecked = mode == MesaShield.Core.Net.EgressMode.Observe;
        RbEgressEnforce.IsChecked = mode == MesaShield.Core.Net.EgressMode.Enforce;
        EgressStatusText.Text = App.NetworkLearner.IsLearning
            ? $"Learning this machine's normal network behavior ({App.NetworkLearner.Observations} connections seen). Enforcement holds off until it has a baseline."
            : $"Baseline established. Enforce mode will block data heading to destinations your programs have never used. Run as administrator for active blocking.";
        EgressList.ItemsSource = _egressRows;
    }

    public void OnEgressDecision(MesaShield.Core.Net.EgressDecision d)
    {
        _egressRows.Insert(0, new EgressRow
        {
            Time = DateTime.Now.ToString("HH:mm:ss"),
            Process = d.Observation.ProcessName,
            Destination = $"{d.Observation.RemoteAddress}:{d.Observation.RemotePort}",
            Action = d.Action.ToString(),
            Reason = d.Reason,
            Observation = d.Observation,
        });
        while (_egressRows.Count > 300) _egressRows.RemoveAt(_egressRows.Count - 1);

        if (App.Settings.ShowNotifications && d.Action == MesaShield.Core.Net.EgressAction.Block)
            _tray?.Notify("Blocked data leaving", $"{d.Observation.ProcessName} → {d.Observation.RemoteAddress}\n{d.Reason}", warning: true);
    }

    private void SaveEgress_Click(object sender, RoutedEventArgs e)
    {
        var mode = RbEgressEnforce.IsChecked == true ? MesaShield.Core.Net.EgressMode.Enforce
            : RbEgressObserve.IsChecked == true ? MesaShield.Core.Net.EgressMode.Observe
            : MesaShield.Core.Net.EgressMode.Off;
        App.Settings.EgressMode = mode;
        App.Settings.Save();
        App.Egress.Mode = mode;
        if (mode != MesaShield.Core.Net.EgressMode.Off && !App.EgressWatch.IsRunning) App.EgressWatch.Start();
        else if (mode == MesaShield.Core.Net.EgressMode.Off && App.EgressWatch.IsRunning) App.EgressWatch.Dispose();
        MessageBox.Show($"Egress control set to {mode}.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ApproveEgress_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in EgressList.SelectedItems.Cast<EgressRow>())
            if (row.Observation is not null) App.Egress.Approve(row.Observation);
        App.Egress.Save(App.EgressStatePath);
    }

    private async void BlockEgress_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in EgressList.SelectedItems.Cast<EgressRow>())
        {
            if (row.Observation is null) continue;
            App.Egress.Deny(row.Observation);
            try { await App.Firewall.BlockRemoteForApplicationAsync(row.Process, row.Observation.RemoteAddress, "Blocked by user from Traffic view."); }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Blocking traffic in the firewall needs administrator rights. Restart MesaShield as administrator.", "MesaShield");
                break;
            }
            catch { }
        }
        App.Egress.Save(App.EgressStatePath);
    }

    // ---- Privacy page -----------------------------------------------------

    private sealed record AuditRow(string Time, string Host, string Purpose, string Result);

    private void LoadPrivacyPage()
    {
        var s = App.Settings;
        RbStandard.IsChecked = s.PrivacyMode == MesaShield.Core.Privacy.PrivacyMode.Standard;
        RbStrict.IsChecked = s.PrivacyMode == MesaShield.Core.Privacy.PrivacyMode.Strict;
        RbOffline.IsChecked = s.PrivacyMode == MesaShield.Core.Privacy.PrivacyMode.Offline;
        TxtMirror.Text = s.LocalSignatureMirror;
        TxtRetention.Text = s.LogRetentionDays.ToString();

        EndpointsText.Text =
            "• bazaar.abuse.ch — download public malware-hash lists. Sends nothing about you.\n" +
            "• api.github.com — check your repo for app updates. Sends nothing about you.\n" +
            "• virustotal.com — optional; only if you set a key. Sends a file's fingerprint (hash), never the file.\n\n" +
            "There is no MesaShield company server, and no analytics or telemetry anywhere in the app.";

        RefreshAudit_Click(this, new RoutedEventArgs());
    }

    private void RefreshAudit_Click(object sender, RoutedEventArgs e)
    {
        var rows = new List<AuditRow>();
        try
        {
            if (File.Exists(App.PrivacyAuditPath))
            {
                foreach (var line in File.ReadLines(App.PrivacyAuditPath).Reverse().Take(200))
                {
                    try
                    {
                        var entry = System.Text.Json.JsonSerializer.Deserialize<MesaShield.Core.Privacy.NetworkAuditEntry>(line);
                        if (entry is not null)
                            rows.Add(new AuditRow(entry.At.ToLocalTime().ToString("g"), entry.Host, entry.Purpose.ToString(),
                                (entry.Allowed ? "allowed — " : "BLOCKED — ") + entry.Reason));
                    }
                    catch { }
                }
            }
        }
        catch { }
        AuditList.ItemsSource = rows;
        if (rows.Count == 0)
            AuditList.ItemsSource = new[] { new AuditRow("—", "—", "—", "No outbound connections recorded yet.") };
    }

    private void SavePrivacy_Click(object sender, RoutedEventArgs e)
    {
        var s = App.Settings;
        s.PrivacyMode = RbOffline.IsChecked == true ? MesaShield.Core.Privacy.PrivacyMode.Offline
            : RbStrict.IsChecked == true ? MesaShield.Core.Privacy.PrivacyMode.Strict
            : MesaShield.Core.Privacy.PrivacyMode.Standard;
        s.LocalSignatureMirror = TxtMirror.Text.Trim();
        if (int.TryParse(TxtRetention.Text, out var days) && days >= 0) s.LogRetentionDays = days;
        s.Save();

        // Apply immediately.
        App.Privacy.Mode = s.PrivacyMode;
        if (s.PrivacyMode != MesaShield.Core.Privacy.PrivacyMode.Standard)
        {
            // In Strict/Offline, cloud lookups are off regardless of key.
            App.Engine.Reputation = null;
        }
        MessageBox.Show($"Privacy mode set to {s.PrivacyMode}. This is enforced for every connection immediately.",
            "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void EraseData_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Erase all learned baselines, models, and activity logs on this machine? This can't be undone.",
                "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        App.EraseAllLearnedData();
        _ = RefreshActivityAsync();
        RefreshAudit_Click(this, new RoutedEventArgs());
        MessageBox.Show("All learned data and logs erased.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void LoadSettingsIntoUi()
    {
        var s = App.Settings;
        ChkRealTime.IsChecked = s.RealTimeProtectionEnabled;
        ChkProcess.IsChecked = s.ProcessMonitoringEnabled;
        ChkBehavior.IsChecked = s.BehaviorGuardEnabled;
        ChkAmsi.IsChecked = s.AmsiScriptScanningEnabled;
        ChkUsb.IsChecked = s.UsbAutoScanEnabled;
        ChkCloud.IsChecked = s.CloudLookupEnabled;
        ChkAdaptive.IsChecked = s.AdaptiveLearningEnabled;
        ChkMl.IsChecked = s.MlClassifierEnabled;
        ChkEtw.IsChecked = s.EtwMonitoringEnabled;
        LearnerStatusText.Text = App.Learner.IsLearning
            ? $"Adaptive learning: still learning this machine's normal ({App.Learner.Observations} events seen; needs ~300 before it starts flagging)."
            : $"Adaptive learning: active — baseline from {App.Learner.Observations:N0} events. ML model: {App.Classifier?.Version ?? "none"}. Deep monitor: {App.Etw.Status}.";
        ChkAutoUpdate.IsChecked = s.AutoUpdateEnabled;
        ChkRunAtStartup.IsChecked = s.RunAtStartup;
        ChkNotifications.IsChecked = s.ShowNotifications;
        TxtVtKey.Text = s.VirusTotalApiKey ?? "";
        TxtUpdateChannel.Text = s.UpdateChannel;
        ChkFleet.IsChecked = s.FleetReportingEnabled;
        TxtFleetFolder.Text = s.FleetSharedFolder;

        foreach (var f in Enum.GetNames<ScheduleFrequency>()) { CmbScanFreq.Items.Add(f); CmbSigFreq.Items.Add(f); }
        foreach (var sc in Enum.GetNames<ScheduledScanScope>()) CmbScanScope.Items.Add(sc);
        CmbScanFreq.SelectedItem = s.ScanSchedule.Frequency.ToString();
        CmbSigFreq.SelectedItem = s.SignatureUpdateSchedule.Frequency.ToString();
        CmbScanScope.SelectedItem = s.ScheduledScanScope.ToString();
        TxtScanHour.Text = s.ScanSchedule.Hour.ToString();
        TxtSigHour.Text = s.SignatureUpdateSchedule.Hour.ToString();
    }

    private async void TrainBenign_Click(object sender, RoutedEventArgs e)
    {
        TrainBenignButton.IsEnabled = false;
        TrainBenignStatus.Text = "Scanning this PC's installed software and learning its profile… (this can take a minute)";
        try
        {
            var progress = new Progress<string>(m => TrainBenignStatus.Text = m);
            var model = await Task.Run(() => BenignTrainer.TrainFromThisPc(progress));
            if (model is null)
            {
                TrainBenignStatus.Text = "Couldn't find enough software to learn from. Try running MesaShield as administrator.";
            }
            else
            {
                var json = System.Text.Json.JsonSerializer.Serialize(model, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                Directory.CreateDirectory(Path.GetDirectoryName(App.BenignModelPath)!);
                await File.WriteAllTextAsync(App.BenignModelPath, json);
                App.ReloadBenignModel();
                TrainBenignStatus.Text = $"Done — learned the profile of your software (model {model.Version}, threshold {model.SuspiciousDistance:F1}). Files that don't fit are now flagged.";
                await App.EventLog.LogAsync("ml", "Built known-good (one-class) model from this PC's software.");
            }
        }
        catch (Exception ex)
        {
            TrainBenignStatus.Text = $"Training failed: {ex.Message}";
        }
        finally { TrainBenignButton.IsEnabled = true; }
    }

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        var s = App.Settings;
        s.RealTimeProtectionEnabled = ChkRealTime.IsChecked == true;
        s.ProcessMonitoringEnabled = ChkProcess.IsChecked == true;
        s.BehaviorGuardEnabled = ChkBehavior.IsChecked == true;
        s.AmsiScriptScanningEnabled = ChkAmsi.IsChecked == true;
        s.UsbAutoScanEnabled = ChkUsb.IsChecked == true;
        s.CloudLookupEnabled = ChkCloud.IsChecked == true;
        s.AdaptiveLearningEnabled = ChkAdaptive.IsChecked == true;
        s.MlClassifierEnabled = ChkMl.IsChecked == true;
        s.EtwMonitoringEnabled = ChkEtw.IsChecked == true;
        s.AutoUpdateEnabled = ChkAutoUpdate.IsChecked == true;
        s.RunAtStartup = ChkRunAtStartup.IsChecked == true;
        s.ShowNotifications = ChkNotifications.IsChecked == true;
        s.VirusTotalApiKey = string.IsNullOrWhiteSpace(TxtVtKey.Text) ? null : TxtVtKey.Text.Trim();
        s.UpdateChannel = TxtUpdateChannel.Text.Trim();
        s.FleetReportingEnabled = ChkFleet.IsChecked == true;
        s.FleetSharedFolder = TxtFleetFolder.Text.Trim();

        if (Enum.TryParse<ScheduleFrequency>((string?)CmbScanFreq.SelectedItem, out var sf)) s.ScanSchedule.Frequency = sf;
        if (Enum.TryParse<ScheduleFrequency>((string?)CmbSigFreq.SelectedItem, out var uf)) s.SignatureUpdateSchedule.Frequency = uf;
        if (Enum.TryParse<ScheduledScanScope>((string?)CmbScanScope.SelectedItem, out var scope)) s.ScheduledScanScope = scope;
        if (int.TryParse(TxtScanHour.Text, out var sh) && sh is >= 0 and <= 23) s.ScanSchedule.Hour = sh;
        if (int.TryParse(TxtSigHour.Text, out var uh) && uh is >= 0 and <= 23) s.SignatureUpdateSchedule.Hour = uh;

        s.Save();
        ApplyLiveSettings();
        MessageBox.Show("Settings saved and applied.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    /// <summary>Apply settings that can change while running (start/stop modules, startup entry, engine hooks).</summary>
    private void ApplyLiveSettings()
    {
        var s = App.Settings;

        if (s.RealTimeProtectionEnabled && !App.RealTime.IsRunning) App.RealTime.Start();
        else if (!s.RealTimeProtectionEnabled && App.RealTime.IsRunning) App.RealTime.Stop();

        if (s.BehaviorGuardEnabled && !App.BehaviorWatch.IsRunning) App.BehaviorWatch.Start();
        else if (!s.BehaviorGuardEnabled && App.BehaviorWatch.IsRunning) App.BehaviorWatch.Stop();

        if (s.ProcessMonitoringEnabled && !App.ProcessWatch.IsRunning) App.ProcessWatch.Start();
        else if (!s.ProcessMonitoringEnabled && App.ProcessWatch.IsRunning) App.ProcessWatch.Dispose();

        App.Engine.ScriptScanner = s.AmsiScriptScanningEnabled ? App.Amsi : null;
        App.Engine.Reputation = s.CloudLookupEnabled ? App.Reputation : null;
        App.Engine.Classifier = s.MlClassifierEnabled ? App.Classifier : null;
        App.Engine.BenignModel = s.MlClassifierEnabled ? App.BenignModel : null;
        App.Fleet.SharedFolder = s.FleetReportingEnabled && !string.IsNullOrWhiteSpace(s.FleetSharedFolder) ? s.FleetSharedFolder : null;
        try { App.Fleet.Report(); } catch { }

        if (s.EtwMonitoringEnabled && !App.Etw.IsRunning) App.Etw.Start();
        else if (!s.EtwMonitoringEnabled && App.Etw.IsRunning) App.Etw.Dispose();

        try
        {
            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (exePath is not null) StartupManager.SetEnabled(s.RunAtStartup, exePath);
        }
        catch { /* non-fatal */ }

        UpdateRealTimeCard();
    }
}
