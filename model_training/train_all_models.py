"""
Master Training Script - Train All Models
Trains URL, NLP, CNN, and GNN models sequentially
"""

import subprocess
import sys
from datetime import datetime

print("="*80)
print("MASTER TRAINING SCRIPT - All Models")
print("="*80)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

models_to_train = [
    {
        'name': 'URL Model (XGBoost + Ensemble)',
        'script': 'train_url_model.py',
        'description': 'URL structure and feature analysis'
    },
    {
        'name': 'NLP Model (BERT)',
        'script': 'train_nlp_model.py',
        'description': 'Email/SMS text analysis'
    },
    {
        'name': 'CNN Model (ResNet-50)',
        'script': 'train_cnn_model.py',
        'description': 'Visual webpage analysis'
    },
    {
        'name': 'GNN Model (Graph Neural Network)',
        'script': 'train_gnn_model.py',
        'description': 'Domain relationship analysis'
    }
]

results = []

for i, model in enumerate(models_to_train, 1):
    print("\n" + "="*80)
    print(f"[{i}/{len(models_to_train)}] Training {model['name']}")
    print(f"Description: {model['description']}")
    print("="*80 + "\n")
    
    try:
        result = subprocess.run(
            [sys.executable, model['script']],
            capture_output=False,
            text=True,
            check=True
        )
        
        results.append({
            'model': model['name'],
            'status': 'SUCCESS',
            'script': model['script']
        })
        
        print(f"\n[+] {model['name']} training completed successfully!")
        
    except subprocess.CalledProcessError as e:
        results.append({
            'model': model['name'],
            'status': 'FAILED',
            'script': model['script']
        })
        print(f"\n[!] {model['name']} training failed!")
        print(f"Error: {e}")
    
    except Exception as e:
        results.append({
            'model': model['name'],
            'status': 'ERROR',
            'script': model['script']
        })
        print(f"\n[!] Unexpected error training {model['name']}")
        print(f"Error: {e}")

# Summary
print("\n\n" + "="*80)
print("TRAINING SUMMARY")
print("="*80)

for result in results:
    status_symbol = "[+]" if result['status'] == 'SUCCESS' else "[!]"
    print(f"{status_symbol} {result['model']}: {result['status']}")

success_count = sum(1 for r in results if r['status'] == 'SUCCESS')
total_count = len(results)

print("\n" + "="*80)
print(f"Completed: {success_count}/{total_count} models trained successfully")
print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)

if success_count == total_count:
    print("\n[+] All models trained successfully!")
    print("[+] Your phishing detection system is ready!")
else:
    print(f"\n[!] {total_count - success_count} model(s) failed to train")
    print("[!] Check the error messages above")
