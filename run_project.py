"""
FILE NAME: run_project.py
FILE PATH: run_project.py
PURPOSE: Master execution launcher for Phishing Email Detection & Awareness Suite.
         Verifies dataset presence, model training, database initialization,
         and starts the Uvicorn web server hosting the REST API & Dashboard.
"""

import os
import sys
import uvicorn

def main():
    print("=" * 70)
    print("   PHISHING EMAIL DETECTION & DEFENSIVE AWARENESS DASHBOARD   ")
    print("=" * 70)
    
    # Step 1: Ensure dataset exists
    dataset_file = "data/phishing_email_dataset.csv"
    if not os.path.exists(dataset_file):
        print("[*] Synthetic dataset not found. Generating now...")
        from data.generate_dataset import generate_synthetic_dataset
        generate_synthetic_dataset()
    else:
        print(f"[+] Dataset verified: {dataset_file}")

    # Step 2: Ensure ML model trained
    model_file = "models/phishing_model.joblib"
    if not os.path.exists(model_file):
        print("[*] Trained model artifact not found. Training model now...")
        from ml.train_model import train_and_evaluate
        train_and_evaluate()
    else:
        print(f"[+] ML Model verified: {model_file}")

    # Step 3: Initialize Database
    from backend.database import init_db
    init_db()
    print("[+] Database initialized.")

    # Step 4: Launch Server
    print("\n[+] Starting FastAPI server and Web Dashboard...")
    print("    • URL:  http://127.0.0.1:8000")
    print("    • Docs: http://127.0.0.1:8000/docs\n")
    
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    main()
