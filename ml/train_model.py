"""
FILE NAME: train_model.py
FILE PATH: ml/train_model.py
PURPOSE: Trains and benchmarks multiple ML classifiers (Logistic Regression, Naive Bayes, Random Forest)
         using a hybrid feature representation: TF-IDF n-grams + structured phishing indicators.
         Saves the best-performing model and vectorizer to models/phishing_model.joblib.
"""

import os
import sys
import json
import joblib

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from backend.services.feature_extractor import extract_email_features

def build_structured_matrix(df: pd.DataFrame) -> np.ndarray:
    """Extracts structured indicator feature vectors for each row in dataframe."""
    feature_rows = []
    for _, row in df.iterrows():
        feats = extract_email_features(
            sender=str(row.get("sender", "")),
            subject=str(row.get("subject", "")),
            body=str(row.get("body", "")),
            urls_str=str(row.get("urls", "")),
            attachment_name=str(row.get("attachment_name", ""))
        )
        # Order of numerical features
        vec = [
            feats["urgent_keyword_count"],
            feats["credential_keyword_count"],
            feats["financial_keyword_count"],
            feats["threat_keyword_count"],
            feats["reward_keyword_count"],
            feats["url_count"],
            feats["suspicious_url_count"],
            feats["has_ip_url"],
            feats["has_shortened_url_pattern"],
            feats["sender_domain_length"],
            feats["subdomain_count"],
            feats["has_lookalike_sender"],
            feats["has_mismatched_display_name"],
            feats["suspicious_attachment"],
            feats["generic_greeting"],
            feats["contains_password_request"],
            feats["contains_personal_info_request"],
            feats["exclamation_count"],
            feats["uppercase_ratio"]
        ]
        feature_rows.append(vec)
    return np.array(feature_rows)

def train_and_evaluate(dataset_path="data/phishing_email_dataset.csv", model_output_dir="models"):
    os.makedirs(model_output_dir, exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    
    print(f"[*] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    df = df.dropna(subset=["subject", "body", "label"]).drop_duplicates(subset=["subject", "body"])
    
    # Target encoding: PHISHING -> 1, LEGITIMATE -> 0
    df["target"] = (df["label"] == "PHISHING").astype(int)
    
    # 70% Train, 15% Validation, 15% Test
    train_df, temp_df = train_test_split(df, test_size=0.30, stratify=df["target"], random_state=42)
    val_df, test_df = train_test_split(temp_df, test_size=0.50, stratify=temp_df["target"], random_state=42)
    
    print(f"[+] Splits -> Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")
    
    # Text TF-IDF Vectorization
    tfidf = TfidfVectorizer(max_features=2500, ngram_range=(1, 2), min_df=2)
    train_text = (train_df["subject"].fillna("") + " " + train_df["body"].fillna("")).values
    val_text = (val_df["subject"].fillna("") + " " + val_df["body"].fillna("")).values
    test_text = (test_df["subject"].fillna("") + " " + test_df["body"].fillna("")).values
    
    X_train_text = tfidf.fit_transform(train_text).toarray()
    X_val_text = tfidf.transform(val_text).toarray()
    X_test_text = tfidf.transform(test_text).toarray()
    
    # Structured Indicator Matrix
    print("[*] Extracting structured cybersecurity features...")
    X_train_struct = build_structured_matrix(train_df)
    X_val_struct = build_structured_matrix(val_df)
    X_test_struct = build_structured_matrix(test_df)
    
    # Combined Feature Matrix
    X_train = np.hstack([X_train_text, X_train_struct])
    X_val = np.hstack([X_val_text, X_val_struct])
    X_test = np.hstack([X_test_text, X_test_struct])
    
    y_train = train_df["target"].values
    y_val = val_df["target"].values
    y_test = test_df["target"].values
    
    # Model Definitions
    candidate_models = {
        "Logistic_Regression": LogisticRegression(max_iter=300, class_weight="balanced", random_state=42),
        "Multinomial_Naive_Bayes": MultinomialNB(),
        "Random_Forest": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    }
    
    evaluation_results = {}
    best_model_name = ""
    best_f1 = -1.0
    best_model_obj = None
    
    print("\n=======================================================")
    print("           MODEL BENCHMARKING & EVALUATION             ")
    print("=======================================================")
    
    for name, model in candidate_models.items():
        # Train
        model.fit(X_train, y_train)
        
        # Test Inference
        y_pred = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)[:, 1]
            auc = round(float(roc_auc_score(y_test, y_proba)), 4)
        else:
            auc = 0.0
            
        acc = round(float(accuracy_score(y_test, y_pred)), 4)
        prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
        rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
        f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        evaluation_results[name] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "confusion_matrix": {
                "TN": cm[0][0],
                "FP": cm[0][1],
                "FN": cm[1][0],
                "TP": cm[1][1]
            }
        }
        
        print(f"\nModel: {name}")
        print(f"  Accuracy:  {acc * 100:.2f}%")
        print(f"  Precision: {prec * 100:.2f}% (Reduces false alerts)")
        print(f"  Recall:    {rec * 100:.2f}% (Catches actual phishing)")
        print(f"  F1-Score:  {f1 * 100:.2f}%")
        print(f"  ROC-AUC:   {auc:.4f}")
        print(f"  Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model_obj = model
            
    print(f"\n[+] Best Selected Model: {best_model_name} (F1 = {best_f1 * 100:.2f}%)")
    
    # Save best bundle
    save_path = os.path.join(model_output_dir, "phishing_model.joblib")
    bundle = {
        "model": best_model_obj,
        "model_name": best_model_name,
        "tfidf": tfidf,
        "feature_count": X_train.shape[1],
        "metrics": evaluation_results[best_model_name]
    }
    joblib.dump(bundle, save_path)
    print(f"[+] Model bundle saved to: {save_path}")
    
    # Save metrics JSON report
    metrics_path = "reports/model_evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(evaluation_results, f, indent=2)
    print(f"[+] Full evaluation metrics saved to: {metrics_path}")
    
    return bundle

if __name__ == "__main__":
    train_and_evaluate()
