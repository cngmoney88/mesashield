#!/usr/bin/env python3
"""
Train the MesaShield offline malware classifier.

MesaShield ships the *inference* engine (pure C#, runs on-device, no cloud). Training the
model happens here, offline, on a labeled corpus of Windows PE files, and produces a small
JSON model that the app loads and updates just like a signature file.

The feature order here MUST match PeFeatureExtractor.FeatureNames in the C# code.

Two ways to get training data:
  1. The EMBER dataset (recommended) — ~1.1M labeled PE feature vectors, open and free:
     https://github.com/elastic/ember  (download, then adapt load_ember() below to map
     EMBER's features onto our 10 features, or extend our feature set to match EMBER).
  2. Your own corpus — a folder of known-malware PE files and a folder of known-clean PE
     files. Point --malware-dir and --clean-dir at them and we extract features directly.

Usage:
    pip install scikit-learn numpy pefile
    python train_classifier.py --malware-dir ./mal --clean-dir ./clean --out classifier.json

Output: classifier.json (weights, bias, per-feature mean/std, thresholds) — drop it in
%LocalAppData%\\MesaShield\\Models\\classifier.json (or publish it via the update feed).
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


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def extract_features(path: str):
    """Mirror of PeFeatureExtractor.Extract in C#. Reads up to 8 MB of the file head."""
    with open(path, "rb") as f:
        head = f.read(8 * 1024 * 1024)
    file_len = os.path.getsize(path)
    is_pe = len(head) >= 2 and head[0:2] == b"MZ"
    entropy = shannon_entropy(head) if len(head) > 256 else 0.0

    num_sections = 0
    header_ratio = 0.0
    if is_pe and len(head) >= 0x40:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if 0 < e_lfanew + 8 <= len(head) and head[e_lfanew:e_lfanew + 2] == b"PE":
            num_sections = int.from_bytes(head[e_lfanew + 6:e_lfanew + 8], "little")
            header_ratio = min(1.0, e_lfanew / file_len) if file_len else 0.0

    printable = sum(1 for b in head if 32 <= b < 127)
    nulls = sum(1 for b in head if b == 0)
    head_len = max(len(head), 1)
    import_hits = sum(1 for s in SUSPICIOUS_IMPORTS if s in head)

    return [
        math.log10(max(file_len, 1)),
        entropy,
        1.0 if is_pe else 0.0,
        min(num_sections, 64),
        1.0 if entropy > 7.2 else 0.0,
        0.0,
        header_ratio,
        printable / head_len,
        nulls / head_len,
        min(import_hits, 16),
    ]


def load_dir(directory: str, label: int):
    X, y = [], []
    for root, _, files in os.walk(directory):
        for name in files:
            try:
                X.append(extract_features(os.path.join(root, name)))
                y.append(label)
            except Exception as e:
                print(f"  skip {name}: {e}", file=sys.stderr)
    return X, y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malware-dir", required=True)
    ap.add_argument("--clean-dir", required=True)
    ap.add_argument("--out", default="classifier.json")
    ap.add_argument("--malicious-threshold", type=float, default=0.9)
    ap.add_argument("--suspicious-threshold", type=float, default=0.7)
    args = ap.parse_args()

    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score

    print("Extracting features...")
    Xm, ym = load_dir(args.malware_dir, 1)
    Xc, yc = load_dir(args.clean_dir, 0)
    X = np.array(Xm + Xc, dtype=float)
    y = np.array(ym + yc, dtype=int)
    print(f"  {len(Xm)} malware, {len(Xc)} clean")
    if len(set(y)) < 2:
        sys.exit("Need both malware and clean samples.")

    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced").fit(Xs, y)

    try:
        auc = cross_val_score(clf, Xs, y, cv=5, scoring="roc_auc").mean()
        print(f"  5-fold ROC AUC: {auc:.3f}")
    except Exception:
        pass

    model = {
        "version": "1",
        "featureNames": FEATURE_NAMES,
        "mean": scaler.mean_.tolist(),
        "std": scaler.scale_.tolist(),
        "weights": clf.coef_[0].tolist(),
        "bias": float(clf.intercept_[0]),
        "maliciousThreshold": args.malicious_threshold,
        "suspiciousThreshold": args.suspicious_threshold,
    }
    with open(args.out, "w") as f:
        json.dump(model, f, indent=2)
    print(f"Wrote {args.out}. Drop it in %LocalAppData%\\MesaShield\\Models\\classifier.json")


if __name__ == "__main__":
    main()
