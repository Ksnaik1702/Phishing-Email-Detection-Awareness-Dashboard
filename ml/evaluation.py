"""
FILE NAME: evaluation.py
FILE PATH: ml/evaluation.py
PURPOSE: Comprehensive ML evaluation report generator.
         Computes precision, recall, F1, specificity, false positive rate,
         and confusion matrices, with cybersecurity operational context.
"""

import json
import os

def print_evaluation_summary(metrics_path="reports/model_evaluation_metrics.json"):
    """Reads saved model benchmark results and prints an analytical cybersecurity report."""
    if not os.path.exists(metrics_path):
        print(f"[-] Evaluation metrics not found at {metrics_path}. Please run ml/train_model.py first.")
        return
        
    with open(metrics_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    print("=" * 65)
    print("      CYBERSECURITY MODEL BENCHMARK & EVALUATION REPORT      ")
    print("=" * 65)
    
    for model_name, metrics in data.items():
        cm = metrics["confusion_matrix"]
        tp = cm["TP"]
        tn = cm["TN"]
        fp = cm["FP"]
        fn = cm["FN"]
        
        print(f"\n[MODEL]: {model_name}")
        print(f"  • Accuracy:        {metrics['accuracy'] * 100:.2f}%")
        print(f"  • Precision:       {metrics['precision'] * 100:.2f}%  (High precision = fewer false alarms)")
        print(f"  • Recall:          {metrics['recall'] * 100:.2f}%  (High recall = fewer missed phishing emails)")
        print(f"  • F1-Score:        {metrics['f1_score'] * 100:.2f}%  (Harmonic mean balancing precision & recall)")
        print(f"  • ROC-AUC:         {metrics['roc_auc']:.4f}")
        print("\n  [CONFUSION MATRIX ANALYSIS]:")
        print(f"    - True Positives (TP):   {tp} (Phishing correctly identified)")
        print(f"    - True Negatives (TN):   {tn} (Legitimate correctly identified)")
        print(f"    - False Positives (FP):  {fp} (Legitimate incorrectly flagged as phishing -> causes alert fatigue)")
        print(f"    - False Negatives (FN):  {fn} (Phishing missed as legitimate -> CRITICAL RISK)")
        
        total = tp + tn + fp + fn
        fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
        fnr = (fn / (fn + tp)) * 100 if (fn + tp) > 0 else 0
        print(f"    - False Positive Rate:   {fpr:.2f}%")
        print(f"    - False Negative Rate:   {fnr:.2f}%")
        print("-" * 65)

if __name__ == "__main__":
    print_evaluation_summary()
