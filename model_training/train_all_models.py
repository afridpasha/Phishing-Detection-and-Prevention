#!/usr/bin/env python
"""Master training script - trains all models in sequence."""

import subprocess
import sys


TRAINING_SCRIPTS = [
    "train_urlnet.py",
    "train_deberta_url.py",
    "train_xgboost_url.py",
    "train_tgt.py",
    "train_securebert_sms.py",
    "train_mdeberta_sms.py",
    "train_setfit_sms.py",
    "train_phishbert_email.py",
    "train_ai_text_detector.py",
    "train_gat_bec.py",
    "train_codebert_html.py",
    "train_yolov8_qr.py",
    "train_clip_brand.py",
    "train_layoutlm_login.py",
    "train_efficientnet_visual.py",
    "train_steg_cnn.py",
    "train_meta_learner.py",
]


def run_training_script(script_name: str) -> bool:
    print("\n" + "=" * 80)
    print(f"Training: {script_name}")
    print("=" * 80 + "\n")

    try:
        result = subprocess.run(
            [sys.executable, script_name],
            cwd="model_training",
            check=True,
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        print(f"[OK] {script_name} completed successfully")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"[FAIL] {script_name} failed:")
        print(exc.stderr)
        return False


def main() -> int:
    print("=" * 80)
    print("PHISHING SHIELD 2.0 - MASTER TRAINING SCRIPT")
    print("=" * 80)
    print(f"\nTraining {len(TRAINING_SCRIPTS)} models...\n")

    results = {script: run_training_script(script) for script in TRAINING_SCRIPTS}

    print("\n" + "=" * 80)
    print("TRAINING SUMMARY")
    print("=" * 80)

    for script, success in results.items():
        status = "[OK] SUCCESS" if success else "[FAIL] FAILED"
        print(f"{status}: {script}")

    total = len(results)
    successful = sum(results.values())
    print(f"\nTotal: {successful}/{total} models trained successfully")
    return 0 if successful == total else 1


if __name__ == "__main__":
    sys.exit(main())

