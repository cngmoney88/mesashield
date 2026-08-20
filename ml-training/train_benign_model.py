#!/usr/bin/env python3
"""
Train MesaShield's one-class "known-good" model.

This learns what legitimate software looks like from a folder of CLEAN Windows PE files
(e.g. your Program Files, Windows\\System32, and your own shop apps) and writes a model that
flags files which don't fit that profile. No malware samples are needed — that's the whole
point, and it's safe to run anywhere.

Usage:
    python train_benign_model.py --clean-dir "C:\\Program Files" --out benign.json
    # (point at one or more folders of trusted software; more files = better)

Output: benign.json → drop in %LocalAppData%\\MesaShield\\Models\\benign.json, or publish it
through the update feed. The feature order matches PeFeatureExtractor.FeatureNames in the app.
"""
import argparse, json, math, os, sys

FEATURE_NAMES = [
    "size_log", "entropy_overall", "is_pe", "num_sections", "high_entropy",
    "has_tls", "header_size_ratio", "printable_ratio", "null_ratio", "imports_hint",
]
SUSPICIOUS_IMPORTS = [
    b"VirtualAlloc", b"VirtualProtect", b"WriteProcessMemory", b"CreateRemoteThread",
    b"LoadLibrary", b"GetProcAddress", b"WinExec", b"ShellExecute", b"URLDownloadToFile",
    b"CryptEncrypt", b"RegSetValue", b"SetWindowsHookEx", b"IsDebuggerPresent",
]


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data); e = 0.0
    for c in counts:
        if c:
            p = c / n; e -= p * math.log2(p)
    return e


def extract_features(path):
    with open(path, "rb") as f:
        head = f.read(8 * 1024 * 1024)
    file_len = os.path.getsize(path)
    is_pe = len(head) >= 2 and head[0:2] == b"MZ"
    if not is_pe:
        return None
    entropy = shannon_entropy(head) if len(head) > 256 else 0.0
    num_sections = 0; header_ratio = 0.0
    if len(head) >= 0x40:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if 0 < e_lfanew + 8 <= len(head) and head[e_lfanew:e_lfanew + 2] == b"PE":
            num_sections = int.from_bytes(head[e_lfanew + 6:e_lfanew + 8], "little")
            header_ratio = min(1.0, e_lfanew / file_len) if file_len else 0.0
    printable = sum(1 for b in head if 32 <= b < 127)
    nulls = sum(1 for b in head if b == 0)
    hl = max(len(head), 1)
    imports = sum(1 for s in SUSPICIOUS_IMPORTS if s in head)
    return [
        math.log10(max(file_len, 1)), entropy, 1.0, min(num_sections, 64),
        1.0 if entropy > 7.2 else 0.0, 0.0, header_ratio,
        printable / hl, nulls / hl, min(imports, 16),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clean-dir", required=True, nargs="+", help="one or more folders of trusted PE files")
    ap.add_argument("--out", default="benign.json")
    ap.add_argument("--margin", type=float, default=1.5, help="threshold margin above the 99th-percentile benign distance")
    args = ap.parse_args()

    feats = []
    for root_dir in args.clean_dir:
        for root, _, files in os.walk(root_dir):
            for name in files:
                if not name.lower().endswith((".exe", ".dll", ".sys")):
                    continue
                try:
                    v = extract_features(os.path.join(root, name))
                    if v:
                        feats.append(v)
                except Exception:
                    pass
    if len(feats) < 50:
        sys.exit(f"Only {len(feats)} PE files found — point at bigger folders of trusted software.")
    print(f"Fitting on {len(feats)} known-good files.")

    n = len(FEATURE_NAMES)
    mean = [sum(f[i] for f in feats) / len(feats) for i in range(n)]
    std = [math.sqrt(sum((f[i] - mean[i]) ** 2 for f in feats) / max(len(feats) - 1, 1)) for i in range(n)]

    def distance(f):
        s = 0.0
        for i in range(n):
            sd = std[i] if std[i] > 1e-9 else 1.0
            z = (f[i] - mean[i]) / sd; s += z * z
        return math.sqrt(s / n)

    dists = sorted(distance(f) for f in feats)
    p99 = dists[min(int(len(dists) * 0.99), len(dists) - 1)]
    threshold = max(p99 * args.margin, 3.0)

    model = {
        "version": "1-benign",
        "featureNames": FEATURE_NAMES,
        "mean": mean, "std": std,
        "suspiciousDistance": threshold,
    }
    with open(args.out, "w") as f:
        json.dump(model, f, indent=2)
    print(f"Wrote {args.out} (threshold {threshold:.2f}). "
          f"Drop it in %LocalAppData%\\MesaShield\\Models\\benign.json")


if __name__ == "__main__":
    main()
