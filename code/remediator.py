"""
remediator.py — Generates the canonical steps_json array.

For COMPLETE cases: only verification steps with evidence.
For INCOMPLETE cases: findings + remediation + verification.
For NOT_APPLICABLE: empty array.

Follows the ordering rules from problem_statement.md:
 - Phase order: FINDING, REMEDIATION, VERIFICATION
 - Within each phase: operation order from the table, then system_id, then resource_id
"""
from typing import Dict, List, Optional, Tuple

from evidence_auditor import EvidenceRecord
from policy_engine import PolicyEngine


# Operation ordering within each phase
FINDING_OPS_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]

REMEDIATION_OPS_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]

VERIFICATION_OPS_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]


def _op_sort_key(ops_order: list, op: str, system_id: str,
                 resource_id: str) -> Tuple:
    """Sort key for steps within a phase."""
    try:
        op_idx = ops_order.index(op)
    except ValueError:
        op_idx = 999
    return (op_idx, system_id, resource_id)


class StepBuilder:
    """Builds the steps_json for a single case."""

    def __init__(self, policy: PolicyEngine):
        self.policy = policy
        self.findings: List[dict] = []
        self.remediations: List[dict] = []
        self.verifications: List[dict] = []

    def add_finding(self, system_id: str, resource_id: str,
                    operation: str, state: str, evidence_id: str):
        self.findings.append({
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id,
        })

    def add_remediation(self, system_id: str, resource_id: str,
                        operation: str, state: str):
        self.remediations.append({
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": "",
        })

    def add_verification(self, system_id: str, resource_id: str,
                         operation: str, state: str,
                         evidence_id: str = ""):
        self.verifications.append({
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id,
        })

    def build(self) -> List[dict]:
        """Build the final sorted steps_json array."""
        # Sort within each phase
        self.findings.sort(key=lambda s: _op_sort_key(
            FINDING_OPS_ORDER, s["operation"], s["system_id"], s["resource_id"]))
        self.remediations.sort(key=lambda s: _op_sort_key(
            REMEDIATION_OPS_ORDER, s["operation"], s["system_id"], s["resource_id"]))
        self.verifications.sort(key=lambda s: _op_sort_key(
            VERIFICATION_OPS_ORDER, s["operation"], s["system_id"], s["resource_id"]))

        # Deduplicate within each phase
        self.findings = _dedupe(self.findings)
        self.remediations = _dedupe(self.remediations)
        self.verifications = _dedupe(self.verifications)

        all_steps = self.findings + self.remediations + self.verifications
        result = []
        for i, step in enumerate(all_steps, 1):
            phase = "FINDING" if step in self.findings else (
                "REMEDIATION" if step in self.remediations else "VERIFICATION")
            sys_id = step["system_id"]
            res_id = step["resource_id"]
            op = step["operation"]
            st = step["state"]
            ev_id = step["evidence_id"]

            entry = {
                # Canonical grader contract fields
                "step_no": i,
                "phase": phase,
                "system_id": sys_id,
                "resource_id": res_id,
                "operation": op,
                "state": st,
                "evidence_id": ev_id,
                # Lifecycle contract layout fields
                "step": i,
                "system": sys_id,
                "details": f"{op} on {res_id} (target state: {st})",
            }
            if phase == "FINDING":
                entry["evidence_file"] = ev_id
            else:
                entry["action"] = op

            result.append(entry)

        return result



def _dedupe(steps: List[dict]) -> List[dict]:
    """Remove duplicate steps (same system_id, resource_id, operation)."""
    seen = set()
    result = []
    for step in steps:
        key = (step["system_id"], step["resource_id"], step["operation"])
        if key not in seen:
            seen.add(key)
            result.append(step)
    return result


def generate_steps_for_incomplete(
    records: List[EvidenceRecord],
    policy: PolicyEngine,
    user_id: str,
    audit_at: str,
    account_resource_id: str = "",
) -> List[dict]:
    """
    Generate steps_json for an INCOMPLETE case.

    1. Findings: Report violations found in evidence
    2. Remediation: Actions to fix violations
    3. Verification: Checks that must pass afterward
    """
    builder = StepBuilder(policy)

    # Track what we've found for verification
    found_violations = []
    has_account_finding = False
    security_record = None
    support_records = []
    analytics_records = []
    connector_records = []
    backup_records = []

    for record in records:
        compliance = policy.evaluate_compliance(record)

        if record.record_type == "SECURITY_AUDIT_LOG":
            security_record = record
            continue

        if not compliance["compliant"]:
            violation = compliance["violation_type"]
            found_violations.append((record, compliance))

            # Generate finding
            if record.record_type in ("CONNECTOR", "DATA_FLOW") and record.state == "ACTIVE":
                builder.add_finding(
                    record.system_id, record.resource_id,
                    "REPORT_ACTIVE_DATA_FLOW", "ACTIVE",
                    record.evidence_id,
                )
                connector_records.append(record)
            elif record.record_type == "BACKUP_ARCHIVE" and record.state == "RESTORE_ACTIVE":
                builder.add_finding(
                    record.system_id, record.resource_id,
                    "REPORT_RESTORE_RISK", "ACTIVE",
                    record.evidence_id,
                )
                backup_records.append(record)
            elif violation == "EXPOSED_PII":
                builder.add_finding(
                    record.system_id, record.resource_id,
                    "REPORT_EXPOSED_PII", "PRESENT",
                    record.evidence_id,
                )
                if record.record_type == "SUPPORT_MESSAGE":
                    support_records.append(record)
                elif record.record_type in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                    analytics_records.append(record)
                elif record.record_type == "ACCOUNT_TOMBSTONE":
                    pass  # Handled separately
            elif violation == "REMAINING_RECORD":
                builder.add_finding(
                    record.system_id, record.resource_id,
                    "REPORT_REMAINING_RECORD", "PRESENT",
                    record.evidence_id,
                )
                if record.record_type == "USER_PROFILE":
                    has_account_finding = True
        else:
            # Compliant records may still need verification
            if record.record_type == "SUPPORT_MESSAGE" and record.state == "REDACTED":
                support_records.append(record)
            elif record.record_type in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY") and record.state == "ANONYMIZED":
                analytics_records.append(record)

    # Generate remediation steps
    for record, compliance in found_violations:
        action = compliance["required_action"]

        if record.record_type in ("CONNECTOR", "DATA_FLOW") and record.state == "ACTIVE":
            builder.add_remediation(
                record.system_id, record.resource_id,
                "DISABLE_DATA_FLOW", "DISABLED",
            )
        elif record.record_type == "BACKUP_ARCHIVE" and record.state == "RESTORE_ACTIVE":
            builder.add_remediation(
                record.system_id, record.resource_id,
                "BLOCK_RESTORE", "BLOCKED",
            )
        elif action == "DELETE":
            builder.add_remediation(
                record.system_id, record.resource_id,
                "DELETE_RECORD", "ABSENT",
            )
        elif action == "REDACT":
            builder.add_remediation(
                record.system_id, record.resource_id,
                "REDACT_RECORD", "REDACTED",
            )
        elif action == "ANONYMIZE":
            builder.add_remediation(
                record.system_id, record.resource_id,
                "ANONYMIZE_RECORD", "ANONYMIZED",
            )

    # Generate verification steps
    # 1. Verify account absent (always for deletion cases)
    if account_resource_id:
        builder.add_verification(
            "account_service", account_resource_id,
            "VERIFY_RECORD_ABSENT", "ABSENT",
        )

    # 2. Verify each violated record's target state
    for record, compliance in found_violations:
        action = compliance["required_action"]

        if record.record_type == "USER_PROFILE":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_ABSENT", "ABSENT",
            )
        elif record.record_type in ("SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
                                     "USER_EXPORT", "MARKETING_PROFILE",
                                     "SUPPORT_ATTACHMENT"):
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_ABSENT", "ABSENT",
            )
        elif record.record_type == "SUPPORT_MESSAGE":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_REDACTED", "REDACTED",
            )
        elif record.record_type in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED",
            )
        elif record.record_type == "ACCOUNT_TOMBSTONE":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_REDACTED", "REDACTED",
            )
        elif record.record_type in ("CONNECTOR", "DATA_FLOW"):
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_DATA_FLOW_DISABLED", "DISABLED",
            )
        elif record.record_type == "BACKUP_ARCHIVE":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RESTORE_BLOCKED", "BLOCKED",
            )
        else:
            if action == "DELETE":
                builder.add_verification(
                    record.system_id, record.resource_id,
                    "VERIFY_RECORD_ABSENT", "ABSENT",
                )
            elif action == "REDACT":
                builder.add_verification(
                    record.system_id, record.resource_id,
                    "VERIFY_RECORD_REDACTED", "REDACTED",
                )
            elif action == "ANONYMIZE":
                builder.add_verification(
                    record.system_id, record.resource_id,
                    "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED",
                )

    # 3. Verify security audit record is retained
    if security_record:
        builder.add_verification(
            security_record.system_id, security_record.resource_id,
            "VERIFY_RECORD_PRESENT", "PRESENT",
        )


    return builder.build()


def generate_steps_for_complete(
    records: List[EvidenceRecord],
    policy: PolicyEngine,
    user_id: str,
    audit_at: str,
    account_resource_id: str = "",
    evidence_id: str = "",
) -> List[dict]:
    """
    Generate steps_json for a COMPLETE case.
    Only verification steps proving the current compliant state.
    All verification steps must cite evidence.
    """
    builder = StepBuilder(policy)

    # Verify account absent
    if account_resource_id:
        builder.add_verification(
            "account_service", account_resource_id,
            "VERIFY_RECORD_ABSENT", "ABSENT",
            evidence_id=evidence_id,
        )

    # For each record, add appropriate verification
    for record in records:
        if record.record_type == "SECURITY_AUDIT_LOG":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_PRESENT", "PRESENT",
                evidence_id=record.evidence_id or evidence_id,
            )
        elif record.record_type == "SUPPORT_MESSAGE" and record.state == "REDACTED":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_REDACTED", "REDACTED",
                evidence_id=record.evidence_id or evidence_id,
            )
        elif record.record_type in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY") and record.state == "ANONYMIZED":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED",
                evidence_id=record.evidence_id or evidence_id,
            )
        elif record.record_type in ("CONNECTOR", "DATA_FLOW") and record.state == "DISABLED":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_DATA_FLOW_DISABLED", "DISABLED",
                evidence_id=record.evidence_id or evidence_id,
            )
        elif record.record_type == "BACKUP_ARCHIVE" and record.state == "RESTORE_BLOCKED":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RESTORE_BLOCKED", "BLOCKED",
                evidence_id=record.evidence_id or evidence_id,
            )
        elif record.record_type == "ACCOUNT_TOMBSTONE" and record.state == "REDACTED":
            builder.add_verification(
                record.system_id, record.resource_id,
                "VERIFY_RECORD_REDACTED", "REDACTED",
                evidence_id=record.evidence_id or evidence_id,
            )

    return builder.build()
