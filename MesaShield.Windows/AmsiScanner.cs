using System.Runtime.InteropServices;
using MesaShield.Core;

namespace MesaShield.Windows;

/// <summary>
/// Wraps the Windows Antimalware Scan Interface (AMSI). AmsiScanBuffer hands a buffer
/// to every AMSI provider registered on the machine (Windows Defender, and any other
/// AV) and returns their combined verdict. This lets MesaShield scan script content —
/// including scripts decoded only at runtime, which is how fileless attacks hide — and
/// leverage the OS's own detection alongside our engine.
///
/// AMSI is a documented, user-mode API; no elevation or driver required.
/// </summary>
public sealed class AmsiScanner : IScriptScanner, IDisposable
{
    private IntPtr _context;
    private bool _initialized;

    public bool IsAvailable => _initialized;

    public AmsiScanner(string appName = "MesaShield")
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            _initialized = AmsiInitialize(appName, out _context) == 0;
        }
        catch (DllNotFoundException)
        {
            _initialized = false; // AMSI unavailable on this OS build
        }
    }

    public enum AmsiResult
    {
        Clean = 0,
        NotDetected = 1,
        /// <summary>32768+ means the provider flagged it as malware.</summary>
        Detected = 32768,
    }

    /// <summary>Scan a script/content buffer. Returns true if AMSI flags it as malicious.</summary>
    public bool ScanContent(string content, string contentName, out int rawResult)
    {
        rawResult = (int)AmsiResult.NotDetected;
        if (!_initialized) return false;

        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        var hr = AmsiScanBuffer(_context, bytes, (uint)bytes.Length, contentName, IntPtr.Zero, out var result);
        if (hr != 0) return false;

        rawResult = result;
        return AmsiResultIsMalware(result);
    }

    /// <summary>Scan a file's textual content through AMSI (implements <see cref="IScriptScanner"/>).</summary>
    public async Task<bool> ScanFileMaliciousAsync(string path, CancellationToken ct = default)
    {
        if (!_initialized) return false;
        try
        {
            var content = await File.ReadAllTextAsync(path, ct).ConfigureAwait(false);
            return ScanContent(content, Path.GetFileName(path), out _);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static bool AmsiResultIsMalware(int result) => result >= (int)AmsiResult.Detected;

    // ---- P/Invoke: amsi.dll ----------------------------------------------

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanBuffer(
        IntPtr amsiContext, byte[] buffer, uint length, string contentName,
        IntPtr amsiSession, out int result);

    public void Dispose()
    {
        if (_initialized && _context != IntPtr.Zero)
        {
            try { AmsiUninitialize(_context); } catch { /* shutting down */ }
            _context = IntPtr.Zero;
            _initialized = false;
        }
    }
}
