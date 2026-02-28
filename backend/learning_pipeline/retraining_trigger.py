import subprocess
import sys


def trigger_retraining(reason: str) -> dict:
    try:
        proc = subprocess.run([sys.executable, 'run_training.py'], cwd='.', check=False, capture_output=True, text=True)
        return {
            'triggered': proc.returncode == 0,
            'reason': reason,
            'returncode': proc.returncode,
            'stdout': proc.stdout[-2000:],
            'stderr': proc.stderr[-2000:],
        }
    except Exception as exc:
        return {'triggered': False, 'reason': reason, 'error': str(exc)}
