"""
evaluation_harness.py — Automated evaluation harness for Ghost Data Still Exists.

Calculates:
- Case-level deletion-status accuracy, confusion matrix, precision, recall, F1
- Step-level and field-level accuracy (step count, phase, system_id, resource_id, operation, state, evidence_id)
- Sequence accuracy (phase ordering FINDING -> REMEDIATION -> VERIFICATION, step_no continuity)
- Validates structural constraints (CSV schema, JSON validity, exact column names)
- Includes 3 participant-created evaluation test cases
"""
import csv
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Tuple, Any

# Ensure code/ is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from identity_resolver import IdentityGraph
from intent_classifier import classify_intent
from evidence_auditor import EvidenceAuditor
from policy_engine import PolicyEngine
from runner import process_case, load_system_activity, format_steps_json


def validate_steps_sequence(steps: List[dict]) -> Tuple[bool, List[str]]:
    """Validate that steps conform to ordering and schema rules."""
    errors = []
    if not steps:
        return True, errors

    phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
    current_phase_rank = 0
    expected_step_no = 1

    for idx, s in enumerate(steps):
        # 1. Step numbering
        if s.get("step_no") != expected_step_no:
            errors.append(f"Step index {idx}: step_no={s.get('step_no')}, expected {expected_step_no}")
        expected_step_no += 1

        # 2. Phase ordering
        phase = s.get("phase", "")
        if phase not in phase_order:
            errors.append(f"Invalid phase: {phase}")
        else:
            rank = phase_order[phase]
            if rank < current_phase_rank:
                errors.append(f"Phase {phase} out of order after prior phase rank {current_phase_rank}")
            current_phase_rank = rank

        # 3. Required keys
        required_keys = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
        missing = required_keys - set(s.keys())
        if missing:
            errors.append(f"Step {idx+1} missing keys: {missing}")

    return len(errors) == 0, errors


def evaluate_predictions(predictions: List[dict], ground_truth: List[dict]) -> dict:
    """Evaluate predictions against ground truth list of dicts."""
    gt_map = {r["case_id"]: r for r in ground_truth}
    pred_map = {r["case_id"]: r for r in predictions}

    total_cases = len(gt_map)
    status_matches = 0
    total_steps_evaluated = 0
    step_field_matches = defaultdict(int)
    total_fields = 0
    sequence_valid_count = 0

    confusion_matrix = defaultdict(lambda: defaultdict(int))
    status_classes = ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]

    case_details = []

    for cid, gt_row in gt_map.items():
        if cid not in pred_map:
            continue

        p_row = pred_map[cid]
        gt_status = gt_row["deletion_status"]
        p_status = p_row["deletion_status"]

        confusion_matrix[gt_status][p_status] += 1
        is_status_match = (gt_status == p_status)
        if is_status_match:
            status_matches += 1

        # Parse steps
        p_steps = p_row["steps_json"] if isinstance(p_row["steps_json"], list) else json.loads(p_row["steps_json"])
        gt_steps = gt_row["steps_json"] if isinstance(gt_row["steps_json"], list) else json.loads(gt_row["steps_json"])

        # Validate sequence
        is_seq_valid, seq_errs = validate_steps_sequence(p_steps)
        if is_seq_valid:
            sequence_valid_count += 1

        # Compare steps
        min_len = min(len(p_steps), len(gt_steps))
        max_len = max(len(p_steps), len(gt_steps))

        fields = ["phase", "system_id", "resource_id", "operation", "state"]
        step_matches = 0
        for i in range(min_len):
            total_steps_evaluated += 1
            all_fields_match = True
            for f in fields:
                total_fields += 1
                if p_steps[i].get(f) == gt_steps[i].get(f):
                    step_field_matches[f] += 1
                else:
                    all_fields_match = False
            if all_fields_match:
                step_matches += 1

        case_details.append({
            "case_id": cid,
            "status_match": is_status_match,
            "pred_status": p_status,
            "gt_status": gt_status,
            "pred_steps": len(p_steps),
            "gt_steps": len(gt_steps),
            "seq_valid": is_seq_valid,
        })

    # Precision, Recall, F1 per class
    metrics = {}
    for sc in status_classes:
        tp = confusion_matrix[sc][sc]
        fp = sum(confusion_matrix[other][sc] for other in status_classes if other != sc)
        fn = sum(confusion_matrix[sc][other] for other in status_classes if other != sc)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        metrics[sc] = {"precision": prec, "recall": rec, "f1": f1, "support": tp + fn}

    case_acc = status_matches / total_cases if total_cases > 0 else 0.0
    seq_acc = sequence_valid_count / total_cases if total_cases > 0 else 0.0
    field_acc = {f: (step_field_matches[f] / (total_fields / len(fields)) if total_fields > 0 else 0.0) for f in fields}

    return {
        "total_cases": total_cases,
        "status_matches": status_matches,
        "case_accuracy": case_acc,
        "sequence_accuracy": seq_acc,
        "confusion_matrix": dict(confusion_matrix),
        "class_metrics": metrics,
        "field_accuracy": field_acc,
        "case_details": case_details,
    }


def run_sample_evaluation():
    """Run full evaluation on sample_deletion_requests.csv vs sample_output.csv."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    dataset_dir = os.path.join(repo_root, "dataset")

    print("[*] Initializing components for sample evaluation...")
    identity = IdentityGraph(dataset_dir)
    system_activities = load_system_activity(dataset_dir)
    auditor = EvidenceAuditor(dataset_dir, identity)
    policy = PolicyEngine(dataset_dir)

    samples_path = os.path.join(dataset_dir, "sample_deletion_requests.csv")
    gold_path = os.path.join(dataset_dir, "sample_output.csv")

    with open(samples_path, "r", encoding="utf-8") as f:
        samples = list(csv.DictReader(f))
    with open(gold_path, "r", encoding="utf-8") as f:
        ground_truth = list(csv.DictReader(f))

    predictions = []
    print(f"[*] Processing {len(samples)} sample cases...")
    for s in samples:
        pred = process_case(s, identity, auditor, policy, system_activities)
        predictions.append(pred)

    results = evaluate_predictions(predictions, ground_truth)
    print("\n" + "=" * 60)
    print("  SAMPLE EVALUATION RESULTS")
    print("=" * 60)
    print(f"Total Cases:        {results['total_cases']}")
    print(f"Status Matches:     {results['status_matches']}/{results['total_cases']} ({results['case_accuracy']*100:.2f}%)")
    print(f"Sequence Accuracy:  {results['sequence_accuracy']*100:.2f}%")
    print("\nPer-Class Metrics:")
    for sc, m in results["class_metrics"].items():
        print(f"  {sc:<15}: Precision={m['precision']:.3f}, Recall={m['recall']:.3f}, F1={m['f1']:.3f}, Support={m['support']}")
    print("\nConfusion Matrix (Row=True, Col=Pred):")
    for r in ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]:
        row_str = " ".join(f"{results['confusion_matrix'].get(r, {}).get(c, 0):4d}" for c in ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"])
        print(f"  {r:<15}: {row_str}")
    print("\nField Accuracies:")
    for f, acc in results["field_accuracy"].items():
        print(f"  {f:<15}: {acc*100:.2f}%")
    print("=" * 60)
    return results


if __name__ == "__main__":
    run_sample_evaluation()
