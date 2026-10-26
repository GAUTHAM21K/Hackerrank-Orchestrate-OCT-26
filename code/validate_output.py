"""
validate_output.py — Validates output.csv against all challenge requirements:
1. Header: case_id,deletion_status,steps_json
2. Row count: exactly 518 rows sorted by case_id
3. Status values: COMPLETE, INCOMPLETE, NOT_APPLICABLE
4. NOT_APPLICABLE: steps_json is empty array []
5. COMPLETE: verification steps only, evidence-backed
6. INCOMPLETE: strict 3-phase progression (FINDING -> REMEDIATION -> VERIFICATION)
   - Every FINDING paired with an actionable concrete REMEDIATION
   - Every REMEDIATION followed by a concrete VERIFICATION check
7. Step indexing: consecutive 1-based integers (1, 2, ..., n) with no gaps or overlaps
8. Field layout:
   - Phase 1 FINDING: step, phase, system, evidence_file, details (and canonical fields)
   - Phase 2 REMEDIATION: step, phase, system, action, details (and canonical fields)
   - Phase 3 VERIFICATION: step, phase, system, action, details (and canonical fields)
"""
import csv
import json
import os
import sys


def validate_output(path: str = "output.csv"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} does not exist.")

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        rows = list(reader)

    print(f"Header: {header}")
    assert header == ["case_id", "deletion_status", "steps_json"], f"Invalid header: {header}"

    print(f"Row count: {len(rows)}")
    assert len(rows) == 518, f"Expected 518 rows, got {len(rows)}"

    case_ids = [r[0] for r in rows]
    assert case_ids == sorted(case_ids), "Rows are not sorted by case_id"

    status_counts = {}
    phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

    for idx, (cid, status, steps_str) in enumerate(rows):
        status_counts[status] = status_counts.get(status, 0) + 1
        assert status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"), f"Invalid status: {status} at {cid}"

        try:
            steps = json.loads(steps_str)
        except Exception as e:
            raise AssertionError(f"Invalid JSON at row {idx+1} ({cid}): {e}")

        assert isinstance(steps, list), f"steps_json must be a JSON array at {cid}"

        # Rule 1: NOT_APPLICABLE must have empty steps
        if status == "NOT_APPLICABLE":
            assert len(steps) == 0, f"NOT_APPLICABLE must have empty steps at {cid}, got {len(steps)}"
            continue

        # Rule 2: COMPLETE cases must have only VERIFICATION steps with evidence
        if status == "COMPLETE":
            assert len(steps) > 0, f"COMPLETE case must have verification steps at {cid}"
            for s in steps:
                assert s.get("phase") == "VERIFICATION", (
                    f"COMPLETE case has non-verification phase at {cid}: {s.get('phase')}"
                )
                assert s.get("evidence_id") or s.get("evidence_file"), (
                    f"COMPLETE case step must have evidence at {cid}: {s}"
                )

        # Rule 3: INCOMPLETE cases must have FINDING, REMEDIATION, and VERIFICATION phases
        if status == "INCOMPLETE":
            assert len(steps) > 0, f"INCOMPLETE case must have steps at {cid}"
            findings = [s for s in steps if s.get("phase") == "FINDING"]
            remediations = [s for s in steps if s.get("phase") == "REMEDIATION"]
            verifications = [s for s in steps if s.get("phase") == "VERIFICATION"]

            assert len(findings) > 0, f"INCOMPLETE case missing FINDING phase at {cid}"
            assert len(remediations) > 0, f"INCOMPLETE case missing REMEDIATION phase at {cid}"
            assert len(verifications) > 0, f"INCOMPLETE case missing VERIFICATION phase at {cid}"

            # Pairing checks: every finding should have a corresponding remediation
            finding_keys = {(s.get("system_id") or s.get("system"), s.get("resource_id")) for s in findings}
            remediation_keys = {(s.get("system_id") or s.get("system"), s.get("resource_id")) for s in remediations}
            unpaired_findings = finding_keys - remediation_keys
            assert not unpaired_findings, f"Unpaired findings without remediation at {cid}: {unpaired_findings}"

            # Every remediation should have a corresponding verification
            verification_keys = {(s.get("system_id") or s.get("system"), s.get("resource_id")) for s in verifications}
            unpaired_remediations = remediation_keys - verification_keys
            assert not unpaired_remediations, f"Unpaired remediation without verification at {cid}: {unpaired_remediations}"

        # Rule 4: Step numbering and strict 3-phase progression
        curr_phase_rank = 0
        for step_idx, s in enumerate(steps, 1):
            # Consecutive 1-based indexing check
            assert s.get("step_no") == step_idx, (
                f"Step numbering error at {cid}: step_no={s.get('step_no')} != {step_idx}"
            )
            assert s.get("step") == step_idx, (
                f"Step numbering error at {cid}: step={s.get('step')} != {step_idx}"
            )

            phase = s.get("phase")
            assert phase in phase_order, f"Invalid phase '{phase}' at {cid} step {step_idx}"
            rank = phase_order[phase]
            assert rank >= curr_phase_rank, (
                f"Phase order violation at {cid}: {phase} appeared after higher phase"
            )
            curr_phase_rank = rank

            # Rule 5: Schema field layout checks
            # Canonical fields
            for k in ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                assert k in s, f"Missing canonical key '{k}' at {cid} step {step_idx}"

            # Contract lifecycle layout fields
            assert "step" in s, f"Missing 'step' key at {cid} step {step_idx}"
            assert "system" in s, f"Missing 'system' key at {cid} step {step_idx}"
            assert "details" in s, f"Missing 'details' key at {cid} step {step_idx}"

            if phase == "FINDING":
                assert "evidence_file" in s, f"Missing 'evidence_file' in FINDING step at {cid}"
            else:
                assert "action" in s, f"Missing 'action' in {phase} step at {cid}"

    print("ALL VALIDATION CHECKS PASSED SUCCESSFULLY!")
    print(f"Status distribution: {status_counts}")
    return True


if __name__ == "__main__":
    validate_output()

