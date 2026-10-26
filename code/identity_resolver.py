"""
identity_resolver.py — Builds the identity graph for each user.

Maps emails (current and historical) to user_id and collects all identifiers
(name, email, phone, email_hash) at various points in time.
"""
import csv
import os
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple


def _parse_ts(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp."""
    ts = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.fromisoformat(ts.rstrip("Z"))


class IdentityGraph:
    """Holds the full identity graph for all users."""

    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        # user_id -> current identity record
        self.users: Dict[str, dict] = {}
        # email (lowered) -> user_id
        self.email_to_user: Dict[str, str] = {}
        # user_id -> set of all known emails (current + historical, lowered)
        self.user_emails: Dict[str, Set[str]] = {}
        # user_id -> set of all known phones
        self.user_phones: Dict[str, Set[str]] = {}
        # user_id -> set of all known email hashes
        self.user_hashes: Dict[str, Set[str]] = {}
        # user_id -> name
        self.user_names: Dict[str, str] = {}

        self._load_identities()
        self._load_audit_log()

    def _load_identities(self):
        path = os.path.join(self.dataset_dir, "user_identities.csv")
        with open(path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                uid = row["user_id"]
                self.users[uid] = row
                email_lower = row["email"].lower().strip()
                self.email_to_user[email_lower] = uid
                self.user_emails.setdefault(uid, set()).add(email_lower)
                self.user_names[uid] = row["name"]
                if row.get("phone"):
                    self.user_phones.setdefault(uid, set()).add(row["phone"])
                if row.get("email_hash"):
                    self.user_hashes.setdefault(uid, set()).add(row["email_hash"])

    def _load_audit_log(self):
        path = os.path.join(self.dataset_dir, "user_audit_log.csv")
        with open(path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                uid = row["user_id"]
                field = row["field_name"]
                old_val = row["old_value"]
                new_val = row["new_value"]

                if field == "email":
                    # Add both old and new emails
                    if old_val:
                        old_lower = old_val.lower().strip()
                        self.user_emails.setdefault(uid, set()).add(old_lower)
                        self.email_to_user[old_lower] = uid
                    if new_val:
                        new_lower = new_val.lower().strip()
                        self.user_emails.setdefault(uid, set()).add(new_lower)
                        self.email_to_user[new_lower] = uid
                elif field == "phone":
                    if old_val:
                        self.user_phones.setdefault(uid, set()).add(old_val)
                    if new_val:
                        self.user_phones.setdefault(uid, set()).add(new_val)
                elif field == "email_hash":
                    if old_val:
                        self.user_hashes.setdefault(uid, set()).add(old_val)
                    if new_val:
                        self.user_hashes.setdefault(uid, set()).add(new_val)

    def resolve_user(self, email: str) -> Optional[str]:
        """Resolve an email to a user_id. Case-insensitive."""
        return self.email_to_user.get(email.lower().strip())

    def get_all_emails(self, user_id: str) -> Set[str]:
        """Get all known emails for a user (lowered)."""
        return self.user_emails.get(user_id, set())

    def get_all_phones(self, user_id: str) -> Set[str]:
        """Get all known phone numbers for a user."""
        return self.user_phones.get(user_id, set())

    def get_all_hashes(self, user_id: str) -> Set[str]:
        """Get all known email hashes for a user."""
        return self.user_hashes.get(user_id, set())

    def get_name(self, user_id: str) -> str:
        """Get the user's current name."""
        return self.user_names.get(user_id, "")

    def get_all_identifiers(self, user_id: str) -> Set[str]:
        """Get all identifiers (emails, phones, hashes, name) for matching."""
        ids = set()
        ids.update(self.get_all_emails(user_id))
        ids.update(self.get_all_phones(user_id))
        ids.update(self.get_all_hashes(user_id))
        name = self.get_name(user_id)
        if name:
            ids.add(name.lower())
        return ids
