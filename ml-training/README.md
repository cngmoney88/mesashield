# MesaShield machine learning

MesaShield learns in two independent, fully on-device ways. Neither uploads your files or
telemetry anywhere — that's the whole point, and it's the privacy edge over commercial AV.

## 1. Adaptive anomaly learning (per machine, automatic)

Built into the app, no training step. Each machine watches its own activity — which programs
launch, from which folders, signed or not, at what times — and builds a small statistical
profile of "normal" (running mean/variance for numeric features, decayed frequency tables for
categorical ones). During a warm-up (~300 events) it only learns. After that it scores each
new event for how surprising it is and flags real outliers with reasons, e.g.:

> Unusual for this machine (88%): first time this program has run; unsigned program from a
> user-writable folder; launched from Temp; running at an unusual time (3:00).

The model lives at `%LocalAppData%\MesaShield\Models\anomaly.json`, is a few KB, and keeps
adapting (old observations fade) so it tracks the machine's *current* normal. Delete that file
to reset learning.

## 2. Offline malware classifier (trained by us, ships like signatures)

The app contains the *inference* engine (pure C#, instant, offline). It scores unknown Windows
programs from static features — file entropy, section count, header shape, suspicious import
names, byte-distribution — using a logistic model stored as a small JSON file. It ships with a
conservative **baseline** model (transparent, expert-set weights) so it works out of the box,
and a model trained on real data drops in to replace it.

### Training a real model

```
pip install scikit-learn numpy pefile
python train_classifier.py --malware-dir ./malware --clean-dir ./clean --out classifier.json
```

- `--malware-dir` / `--clean-dir`: folders of known-malware and known-clean Windows PE files.
  (Even a few thousand of each meaningfully beats the baseline. For a serious model, use the
  open **EMBER** dataset — ~1.1M labeled samples — and adapt the feature mapping.)
- Output `classifier.json` → drop into `%LocalAppData%\MesaShield\Models\classifier.json` on
  each machine, or publish it through the update feed so every machine picks it up.

The feature list and extraction logic in `train_classifier.py` are kept identical to
`PeFeatureExtractor` in the C# app — if you change one, change both, and bump the model version.

### Why not a giant neural net / cloud model?

Because "most private on the market" is the goal. A cloud model means uploading your files or
their features to someone else's server. This design keeps every byte on the machine, stays
fast, and is fully auditable. If you later want deep-learning-grade detection, the same
model-file mechanism can carry an ONNX model and we add an ONNX runtime — still on-device.
