"""
policy_engine.py — Matches discovered records against deletion_rules.csv.

Determines the required action for each record based on its data category
and condition: DELETE, REDACT, ANONYMIZE, or RETAIN.
"""
import csv
import os
from typing import Dict, List, Optional, Tuple

from evidence_auditor import EvidenceRecord


class DeletionRule:
    """A single deletion rule from deletion_rules.csv."""

    def __init__(self, rule_id: str, data_category: str, condition: str,
                 required_action: str):
        self.rule_id = rule_id
        self.data_category = data_category
        self.condition = condition
        self.required_action = required_action


class PolicyEngine:
    """Applies deletion policy to discovered evidence records."""

    def __init__(self, dataset_dir: str):
        self.rules: Dict[str, DeletionRule] = {}
        self.category_rules: Dict[str, DeletionRule] = {}
        self._load_rules(dataset_dir)

    def _load_rules(self, dataset_dir: str):
        path = os.path.join(dataset_dir, "deletion_rules.csv")
        with open(path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rule = DeletionRule(
                    rule_id=row["rule_id"],
                    data_category=row["data_category"],
                    condition=row["condition"],
                    required_action=row["required_action"],
                )
                self.rules[rule.rule_id] = rule
                self.category_rules[rule.data_category] = rule

    def get_required_action(self, record: EvidenceRecord) -> Tuple[str, str]:
        """
        Determine the required action for a record based on its type.

        Returns:
            Tuple of (required_action, rule_id)
            required_action: DELETE, REDACT, ANONYMIZE, RETAIN, or NONE
        """
        record_type = record.record_type

        # Special handling for connectors and backups
        if record_type in ("CONNECTOR", "DATA_FLOW"):
            return "DISABLE", ""
        if record_type == "BACKUP_ARCHIVE":
            return "BLOCK_RESTORE", "rule_14"

        rule = self.category_rules.get(record_type)
        if not rule:
            return "NONE", ""

        return rule.required_action, rule.rule_id

    def evaluate_compliance(self, record: EvidenceRecord) -> dict:
        """
        Evaluate whether a record is compliant with deletion policy.

        Returns a dict with:
        - compliant: bool
        - required_action: str
        - current_state: str
        - violation_type: str (if non-compliant)
        """
        record_type = record.record_type
        required_action, rule_id = self.get_required_action(record)

        result = {
            "required_action": required_action,
            "rule_id": rule_id,
            "current_state": record.state,
            "compliant": False,
            "violation_type": "",
        }

        # 1. Connectors / Data flows
        if record_type in ("CONNECTOR", "DATA_FLOW"):
            if record.state in ("ACTIVE", "1", 1, "ENABLED"):
                result["violation_type"] = "ACTIVE_DATA_FLOW"
            else:
                result["compliant"] = True
            return result

        # 2. Backup archives
        if record_type == "BACKUP_ARCHIVE":
            if record.state in ("RESTORE_ACTIVE", "ACTIVE", "1", 1):
                result["violation_type"] = "RESTORE_RISK"
            else:
                result["compliant"] = True
            return result

        # 3. Standard categories
        if required_action == "DELETE":
            # Record must be absent
            if record.state in ("ABSENT", "DELETED", "NOT_FOUND"):
                result["compliant"] = True
            else:
                result["violation_type"] = "REMAINING_RECORD"

        elif required_action == "REDACT":
            # Record can remain, but PII must be redacted
            if record.state in ("ABSENT", "DELETED", "NOT_FOUND", "REDACTED"):
                result["compliant"] = True
            elif record.has_pii or record.state in ("PRESENT", "FOUND", "IDENTIFIABLE"):
                result["violation_type"] = "EXPOSED_PII"
            else:
                result["compliant"] = True

        elif required_action == "ANONYMIZE":
            # Record can remain, but must be unlinked / anonymized
            if record.state in ("ABSENT", "DELETED", "NOT_FOUND", "ANONYMIZED"):
                result["compliant"] = True
            elif record.has_pii or record.state in ("PRESENT", "FOUND", "IDENTIFIABLE"):
                result["violation_type"] = "EXPOSED_PII"
            else:
                result["compliant"] = True

        elif required_action == "RETAIN":
            # Record must be preserved
            if record.state in ("PRESENT", "FOUND", "RETAINED"):
                result["compliant"] = True
            else:
                result["violation_type"] = "MISSING_RETAINED_RECORD"

        else:
            result["compliant"] = True

        return result

    def should_verify_absent(self, record_type: str) -> bool:
        """Check if a record type requires verification of absence."""
        return record_type in (
            "USER_PROFILE", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
            "USER_EXPORT", "MARKETING_PROFILE", "SUPPORT_ATTACHMENT",
            "SECONDARY_IDENTIFIER"
        )

    def should_verify_redacted(self, record_type: str) -> bool:
        """Check if a record type should be verified as redacted."""
        return record_type in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE")

    def should_verify_anonymized(self, record_type: str) -> bool:
        """Check if a record type should be verified as anonymized."""
        return record_type in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY")

    def should_verify_retained(self, record_type: str) -> bool:
        """Check if a record type must be verified as present/retained."""
        return record_type in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD")
