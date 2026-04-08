"""Compare training metrics across retraining cycles.

Usage:
    python compare_training_metrics.py

Output:
    Prints a formatted table showing F1, Precision, Recall, and Threshold
    across all training runs in training_history.json.
    Useful for showing professor the model improvement over time.
"""

import json
from pathlib import Path
from typing import List, Dict, Any


def load_history() -> List[Dict[str, Any]]:
    history_path = Path("training_history.json")
    if not history_path.exists():
        print("Error: training_history.json not found")
        print("Run training first: python train_xgboost_model.py")
        return []
    
    try:
        return json.loads(history_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error reading history: {e}")
        return []


def print_comparison() -> None:
    history = load_history()
    
    if not history:
        print("No training history found.")
        return
    
    print("\n" + "="*100)
    print("TRAINING METRICS COMPARISON")
    print("="*100)
    print()
    
    # Print header
    print(f"{'Run':<6} {'Timestamp':<26} {'Samples':<10} {'Attack%':<10} {'F1':<8} {'Precision':<12} {'Recall':<8} {'Threshold':<10} {'Best Iter':<10}")
    print("-"*100)
    
    # Print each entry
    for idx, entry in enumerate(history, start=1):
        ts = entry.get("timestamp", "N/A")[:19]  # Show only date and time
        samples = entry.get("sampled_rows", 0)
        attack_ratio = entry.get("attack_ratio", 0)
        f1 = entry.get("val_f1", 0)
        precision = entry.get("val_precision", 0)
        recall = entry.get("val_recall", 0)
        threshold = entry.get("recommended_threshold", 0)
        best_iter = entry.get("best_iteration", 0)
        
        print(
            f"{idx:<6} {ts:<26} {samples:<10} {attack_ratio*100:>8.2f}% {f1:>7.4f} {precision:>11.4f} "
            f"{recall:>7.4f} {threshold:>9.4f} {best_iter:>9}"
        )
    
    # Print improvements
    if len(history) > 1:
        first_f1 = history[0].get("val_f1", 0)
        latest_f1 = history[-1].get("val_f1", 0)
        f1_improvement = (latest_f1 - first_f1) * 100
        
        first_precision = history[0].get("val_precision", 0)
        latest_precision = history[-1].get("val_precision", 0)
        precision_improvement = (latest_precision - first_precision) * 100
        
        first_recall = history[0].get("val_recall", 0)
        latest_recall = history[-1].get("val_recall", 0)
        recall_improvement = (latest_recall - first_recall) * 100
        
        print()
        print("="*100)
        print("IMPROVEMENT SUMMARY (Latest vs First)")
        print("="*100)
        print(f"F1 Score:    {first_f1:.4f} → {latest_f1:.4f}  ({f1_improvement:+.2f}%)")
        print(f"Precision:   {first_precision:.4f} → {latest_precision:.4f}  ({precision_improvement:+.2f}%)")
        print(f"Recall:      {first_recall:.4f} → {latest_recall:.4f}  ({recall_improvement:+.2f}%)")
        print()
        print(f"Total training runs: {len(history)}")
        print("="*100)
        print()


if __name__ == "__main__":
    print_comparison()
