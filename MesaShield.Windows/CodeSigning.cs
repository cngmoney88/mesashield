using System.Runtime.InteropServices;

namespace MesaShield.Windows;

/// <summary>
/// Authenticode trust check. Asks Windows itself (WinVerifyTrust) whether a file carries a valid
/// digital signature that chains to a trusted root — the same check File Explorer's "Digital
/// Signatures" tab shows. MesaShield uses this so it never quarantines a properly signed program
/// (Windows components, Brave, Steam, GIGABYTE tools, etc.) on the strength of a heuristic or an ML
/// guess. Definitive detections (known-malware hash, pattern, AMSI, cloud) still act regardless.
/// </summary>
public static class CodeSigning
{
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    /// <summary>True if <paramref name="path"/> has a valid, trusted Authenticode signature.</summary>
    public static bool IsTrusted(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
        try
        {
            using var fileInfo = new WintrustFileInfoHandle(path);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,   // don't hit the network on every scanned file
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfo.Pointer,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            return result == 0;   // ERROR_SUCCESS: signed and trusted
        }
        catch
        {
            return false;   // any failure → treat as unsigned (fail safe toward scanning, not trusting)
        }
    }

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    /// <summary>Owns the unmanaged WINTRUST_FILE_INFO + the file-path string for one verify call.</summary>
    private sealed class WintrustFileInfoHandle : IDisposable
    {
        public IntPtr Pointer { get; }
        private readonly IntPtr _path;

        public WintrustFileInfoHandle(string path)
        {
            _path = Marshal.StringToCoTaskMemUni(path);
            var info = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = _path,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };
            Pointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(info, Pointer, false);
        }

        public void Dispose()
        {
            if (Pointer != IntPtr.Zero) Marshal.FreeCoTaskMem(Pointer);
            if (_path != IntPtr.Zero) Marshal.FreeCoTaskMem(_path);
        }
    }
}
