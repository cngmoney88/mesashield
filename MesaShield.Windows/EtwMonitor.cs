using System.Diagnostics;
using MesaShield.Core;
using MesaShield.Core.Ml;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace MesaShield.Windows;

/// <summary>
/// Deep real-time telemetry via Event Tracing for Windows (ETW) — the same low-level event
/// stream Microsoft's own tools use. It watches process starts (with real parent-process info)
/// and outbound TCP connections across the whole system, and feeds them to the on-device
/// learners. This is how MesaShield can notice things like "a document reader just made an
/// outbound connection to an address nobody here has ever contacted."
///
/// A kernel ETW session requires administrator rights. When MesaShield isn't elevated, this
/// monitor stays off (and says so) — every other layer keeps working.
/// </summary>
public sealed class EtwMonitor : IDisposable
{
    private readonly AnomalyLearner _processLearner;
    private readonly NetworkAnomalyLearner _networkLearner;
    private readonly ShieldEventLog _log;
    private TraceEventSession? _session;
    private Thread? _thread;
    private readonly Dictionary<int, string> _pidToName = new();
    private readonly object _gate = new();

    public bool IsRunning { get; private set; }
    public string Status { get; private set; } = "stopped";

    public event Action<AnomalyAssessment, string /*context*/>? AnomalyDetected;

    public EtwMonitor(AnomalyLearner processLearner, NetworkAnomalyLearner networkLearner, ShieldEventLog log)
    {
        _processLearner = processLearner;
        _networkLearner = networkLearner;
        _log = log;
    }

    public static bool IsAvailable => OperatingSystem.IsWindows() && (TraceEventSession.IsElevated() ?? false);

    public void Start()
    {
        if (IsRunning) return;
        if (!IsAvailable)
        {
            Status = "unavailable (needs administrator)";
            _ = _log.LogAsync("etw", "Deep monitoring (ETW) is off — run MesaShield as administrator to enable it.");
            return;
        }

        try
        {
            _session = new TraceEventSession("MesaShield-ETW-Kernel");
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Process);

            _session.Source.Kernel.ProcessStart += data =>
            {
                lock (_gate) _pidToName[data.ProcessID] = data.ImageFileName;
                var parent = ResolvePath(data.ParentID);
                var obs = new ProcessObservation
                {
                    ExecutablePath = data.ImageFileName,
                    HourOfDay = DateTime.Now.Hour,
                    ParentPath = parent,
                };
                var a = _processLearner.Observe(obs);
                if (!a.IsLearning && a.SuggestedSeverity is not null)
                    Raise(a, $"process {System.IO.Path.GetFileName(data.ImageFileName)}");
            };

            _session.Source.Kernel.TcpIpConnect += data =>
            {
                var procName = NameFor(data.ProcessID);
                var obs = new NetworkObservation
                {
                    ProcessName = procName,
                    RemoteAddress = data.daddr.ToString(),
                    RemotePort = data.dport,
                };
                var a = _networkLearner.Observe(obs);
                if (!a.IsLearning && a.SuggestedSeverity is not null)
                    Raise(a, $"{procName} → {data.daddr}:{data.dport}");
            };

            _thread = new Thread(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) { _ = _log.LogAsync("etw", $"ETW session ended: {ex.Message}"); }
            }) { IsBackground = true, Name = "MesaShield-ETW" };
            _thread.Start();

            IsRunning = true;
            Status = "running (elevated)";
            _ = _log.LogAsync("etw", "Deep monitoring (ETW) started: process + network telemetry.");
        }
        catch (Exception ex)
        {
            Status = $"failed: {ex.Message}";
            _ = _log.LogAsync("etw", $"Deep monitoring failed to start: {ex.Message}");
            Dispose();
        }
    }

    private string NameFor(int pid)
    {
        lock (_gate)
            if (_pidToName.TryGetValue(pid, out var name)) return System.IO.Path.GetFileNameWithoutExtension(name);
        var resolved = ResolvePath(pid);
        return resolved is null ? $"pid {pid}" : System.IO.Path.GetFileNameWithoutExtension(resolved);
    }

    private static string? ResolvePath(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return p.MainModule?.FileName ?? p.ProcessName; }
        catch { return null; }
    }

    private void Raise(AnomalyAssessment assessment, string context)
    {
        _ = _log.LogAsync(
            assessment.SuggestedSeverity == ThreatSeverity.Malicious ? "anomaly" : "detection",
            $"Deep monitor: unusual ({assessment.Score:P0}) — {string.Join("; ", assessment.Reasons)} [{context}]");
        AnomalyDetected?.Invoke(assessment, context);
    }

    public void Dispose()
    {
        IsRunning = false;
        Status = "stopped";
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
