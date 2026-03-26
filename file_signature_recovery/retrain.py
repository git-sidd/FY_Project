#!/usr/bin/env python3
"""Quick script to delete old models and retrain"""
import os
import subprocess

# Delete old models
models_dir = 'saved_models'
for f in ['cnn_model.keras', 'xgb_type_model.json', 'xgb_malware_model.json']:
    path = os.path.join(models_dir, f)
    if os.path.exists(path):
        os.remove(path)
        print(f"Deleted {path}")

# Run training
print("\nStarting training...")
subprocess.run(['python', 'train.py'], check=False)
