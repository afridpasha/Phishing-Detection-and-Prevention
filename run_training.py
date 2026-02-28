#!/usr/bin/env python
"""Project-level runner for all training scripts."""

import subprocess
import sys


TRAINING_SCRIPTS = [
    'train_urlnet.py',
    'train_deberta_url.py',
    'train_xgboost_url.py',
    'train_tgt.py',
    'train_securebert_sms.py',
    'train_mdeberta_sms.py',
    'train_setfit_sms.py',
    'train_phishbert_email.py',
    'train_ai_text_detector.py',
    'train_gat_bec.py',
    'train_codebert_html.py',
    'train_yolov8_qr.py',
    'train_clip_brand.py',
    'train_layoutlm_login.py',
    'train_efficientnet_visual.py',
    'train_steg_cnn.py',
    'train_meta_learner.py',
]


def main() -> int:
    results = {}
    for script in TRAINING_SCRIPTS:
        print(f'\n=== Running {script} ===')
        proc = subprocess.run([sys.executable, script], cwd='model_training', capture_output=True, text=True)
        print(proc.stdout)
        if proc.returncode != 0:
            print(proc.stderr)
        results[script] = proc.returncode == 0

    ok = sum(results.values())
    total = len(results)
    print(f'\nTraining summary: {ok}/{total} succeeded')
    return 0 if ok == total else 1


if __name__ == '__main__':
    sys.exit(main())
