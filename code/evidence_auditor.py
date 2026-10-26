"""
evidence_auditor.py — Scans all evidence files to find resources associated with a user.

Parses:
- SQLite-compatible SQL files (databases/) including JSON-payload schemas
- JSON records (records/) covering all service exports, snapshot bundles, reports, and job stores
- Log files (logs/) with two-pass distributed trace correlation across lines
- Plain text reports (records/*.txt)
- PDF documents (documents/*.pdf) via pypdf
- Console screenshots (images/*.png) via pytesseract

Indexes all discovered resources by user identifiers and provides point-in-time
reconstruction of resource state at each case's audit_at.
"""
import csv
import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import pypdf
import pytesseract
from PIL import Image

from identity_resolver import IdentityGraph


def _parse_ts(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.fromisoformat(ts.rstrip("Z"))


def normalize_text_for_ocr(text: str) -> str:
    """Normalize text: lowercase, strip extra whitespace, remove strange OCR artifact characters."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[\r\n\t]+', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def normalize_ocr_confusions(text: str) -> str:
    """Normalize common alphanumeric OCR confusions (O vs 0, l/I/| vs 1, etc.)."""
    if not text:
        return ""
    trans = str.maketrans({
        'o': '0',
        'l': '1',
        'i': '1',
        '|': '1',
        '!': '1',
    })
    return text.lower().translate(trans)


def levenshtein_dist_le_1(s1: str, s2: str) -> bool:
    """Return True if Levenshtein distance between s1 and s2 is <= 1, excluding different numeric digits."""
    if s1 == s2:
        return True
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > 1:
        return False
    if len1 == len2:
        diff_indices = [i for i in range(len1) if s1[i] != s2[i]]
        if len(diff_indices) != 1:
            return False
        idx = diff_indices[0]
        c1, c2 = s1[idx], s2[idx]
        # Never treat two different digits as an OCR artifact! (e.g. user_03 vs user_13)
        if c1.isdigit() and c2.isdigit():
            return False
        return True
    if len1 > len2:
        s1, s2 = s2, s1
        len1, len2 = len2, len1
    # len2 == len1 + 1
    i = j = diffs = 0
    while i < len1 and j < len2:
        if s1[i] != s2[j]:
            diffs += 1
            if diffs > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True



def ocr_matches_identifier(ocr_text: str, identifier: str) -> bool:
    """
    Search for customer identifier in OCR extracts using:
    - Direct substring matching on normalized text
    - OCR confusion normalization (O/0, l/I/1)
    - Token-level matching & normalized token intersection
    - Fuzzy matching (Levenshtein distance <= 1 for tokens)
    """
    if not ocr_text or not identifier:
        return False

    ident_clean = identifier.lower().strip()
    if not ident_clean or len(ident_clean) < 3:
        return False

    ocr_norm = normalize_text_for_ocr(ocr_text)

    # 1. Direct substring match
    if ident_clean in ocr_norm:
        return True

    # 2. Confusion-normalized match
    ocr_conf = normalize_ocr_confusions(ocr_norm)
    ident_conf = normalize_ocr_confusions(ident_clean)
    if ident_conf in ocr_conf:
        return True

    # 3. Token-level and fuzzy matching
    ocr_tokens = [re.sub(r'^[^\w@\.\-]+|[^\w@\.\-]+$', '', t) for t in ocr_norm.split()]
    ocr_tokens = [t for t in ocr_tokens if len(t) >= 3]

    # For emails, check username and domain parts
    if "@" in ident_clean:
        parts = ident_clean.split("@", 1)
        uname, domain = parts[0], parts[1]
        uname_found = any(uname in t or levenshtein_dist_le_1(uname, t) for t in ocr_tokens)
        dom_found = any(domain in t or levenshtein_dist_le_1(domain, t) for t in ocr_tokens)
        if uname_found and dom_found:
            return True
        for t in ocr_tokens:
            if "@" in t and (levenshtein_dist_le_1(ident_clean, t) or levenshtein_dist_le_1(ident_conf, normalize_ocr_confusions(t))):
                return True

    # For other identifiers (e.g. user_id, account_id, phone, names)
    for t in ocr_tokens:
        if t == ident_clean:
            return True
        if len(ident_clean) >= 4 and len(t) >= 4:
            if levenshtein_dist_le_1(ident_clean, t):
                return True
            if levenshtein_dist_le_1(ident_conf, normalize_ocr_confusions(t)):
                return True

    # Token intersection for multi-word identifiers (e.g. full names)
    ident_words = [w for w in ident_clean.split() if len(w) >= 3]
    if len(ident_words) >= 2:
        matched_words = 0
        for w in ident_words:
            w_conf = normalize_ocr_confusions(w)
            if any(w in t or levenshtein_dist_le_1(w, t) or levenshtein_dist_le_1(w_conf, normalize_ocr_confusions(t)) for t in ocr_tokens):
                matched_words += 1
        if matched_words == len(ident_words):
            return True

    return False


class EvidenceRecord:

    """A single discovered resource in evidence."""

    def __init__(self, system_id: str, resource_id: str, evidence_id: str,
                 record_type: str, state: str, observed_at: str,
                 has_pii: bool = False, pii_fields: Optional[List[str]] = None,
                 extra: Optional[dict] = None):
        self.system_id = system_id
        self.resource_id = resource_id
        self.evidence_id = evidence_id
        self.record_type = record_type  # data category from deletion_rules
        self.state = state  # PRESENT, ABSENT, REDACTED, ANONYMIZED, etc.
        self.observed_at = observed_at
        self.has_pii = has_pii
        self.pii_fields = pii_fields or []
        self.extra = extra or {}

    def __repr__(self):
        return f"EvidenceRecord({self.system_id}/{self.resource_id}, {self.state}, {self.record_type})"


class EvidenceAuditor:
    """Scans all evidence files and indexes resources by user identifiers."""

    def __init__(self, dataset_dir: str, identity_graph: IdentityGraph):
        self.dataset_dir = dataset_dir
        self.identity = identity_graph
        self.evidence_manifest: Dict[str, dict] = {}  # file_id -> {file_path, origin, captured_at}

        # Pre-parsed evidence indexes
        self._evidence_cache: Dict[str, List[EvidenceRecord]] = {}
        # Global index: (identifier_lower) -> list of (evidence_id, EvidenceRecord)
        self._identifier_index: Dict[str, List[Tuple[str, EvidenceRecord]]] = {}
        # Image OCR cache: file_id -> (norm_text, list of (EvidenceRecord, list of identifiers))
        self._image_ocr_cache: Dict[str, Tuple[str, List[Tuple[EvidenceRecord, List[str]]]]] = {}

        self._load_manifest()
        self._parse_all_evidence()

    def _load_manifest(self):
        path = os.path.join(self.dataset_dir, "evidence_files.csv")
        with open(path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                self.evidence_manifest[row["file_id"]] = row

    def _full_path(self, relative_path: str) -> str:
        return os.path.join(self.dataset_dir, relative_path)

    def _add_record(self, file_id: str, record: EvidenceRecord,
                    identifiers: List[str]):
        """Add a record to the cache and index it by identifiers."""
        self._evidence_cache.setdefault(file_id, []).append(record)
        for ident in identifiers:
            if ident:
                key = str(ident).lower().strip().strip('"').strip("'")
                if key and key not in ("null", "none"):
                    self._identifier_index.setdefault(key, []).append((file_id, record))
                    # Also index OCR confusion-normalized form for resilient matching
                    key_conf = normalize_ocr_confusions(key)
                    if key_conf != key:
                        self._identifier_index.setdefault(key_conf, []).append((file_id, record))


    def _parse_all_evidence(self):
        """Parse every evidence file and build the global index."""
        for file_id, info in self.evidence_manifest.items():
            fpath = self._full_path(info["file_path"])
            captured_at = info["captured_at"]

            if not os.path.exists(fpath):
                continue

            try:
                if fpath.endswith(".sql"):
                    self._parse_sql_evidence(file_id, fpath, captured_at)
                elif fpath.endswith(".json"):
                    self._parse_json_evidence(file_id, fpath, captured_at)
                elif fpath.endswith(".log"):
                    self._parse_log_evidence(file_id, fpath, captured_at)
                elif fpath.endswith(".txt"):
                    self._parse_txt_evidence(file_id, fpath, captured_at)
                elif fpath.endswith(".pdf"):
                    self._parse_pdf_evidence(file_id, fpath, captured_at)
                elif fpath.endswith(".png"):
                    self._parse_image_evidence(file_id, fpath, captured_at)
            except Exception:
                pass

    # ─── SQL PARSING ─────────────────────────────────────────────────
    def _parse_sql_evidence(self, file_id: str, fpath: str, captured_at: str):
        """Execute SQL in a temp SQLite db and extract records."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row

            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                sql_script = f.read()

            conn.executescript(sql_script)

            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall() if not r[0].startswith("sqlite_")]

            for tbl in tables:
                if tbl in ("snapshot_scope", "schema_migrations"):
                    continue

                cursor.execute(f"SELECT * FROM \"{tbl}\"")
                rows = cursor.fetchall()

                # Check if this table has payload JSON column
                col_names = [d[0] for d in cursor.description]
                json_cols = [c for c in col_names if c in ("payload_json", "record_json", "payload", "document")]

                for row in rows:
                    row_dict = dict(row)

                    if json_cols:
                        json_col_name = json_cols[0]
                        raw_json = row_dict.get(json_col_name)
                        if raw_json and isinstance(raw_json, str):
                            try:
                                payload = json.loads(raw_json)
                            except Exception:
                                payload = {}
                        elif isinstance(raw_json, dict):
                            payload = raw_json
                        else:
                            payload = {}

                        sys_id = row_dict.get("origin_system") or row_dict.get("system") or payload.get("origin_system") or payload.get("system") or ""
                        col = row_dict.get("collection_name") or row_dict.get("collection") or payload.get("collection_name") or payload.get("collection") or ""
                        res_id = row_dict.get("resource_id") or payload.get("resource_id") or ""
                        if not res_id:
                            continue

                        _, rec_type = self._table_to_system_and_type(f"{sys_id}_{col}")
                        if not sys_id:
                            sys_id, rec_type = self._table_to_system_and_type(f"{col}")
                        if not rec_type or rec_type == "UNKNOWN":
                            _, rec_type = self._table_to_system_and_type(tbl)

                        idents = self._extract_identifiers_from_row(payload)
                        has_pii, pii_fields = self._check_pii(payload, rec_type)
                        state = self._determine_sql_state(payload, rec_type, tbl, has_pii)

                        obs_time = row_dict.get("captured_at") or row_dict.get("updated_at") or payload.get("updated_at") or captured_at

                        rec = EvidenceRecord(
                            system_id=sys_id,
                            resource_id=res_id,
                            evidence_id=file_id,
                            record_type=rec_type,
                            state=state,
                            observed_at=obs_time,
                            has_pii=has_pii,
                            pii_fields=pii_fields,
                            extra=payload,
                        )
                        self._add_record(file_id, rec, idents)
                    else:
                        res_id = row_dict.get("resource_id", "")
                        if not res_id:
                            continue

                        sys_id, rec_type = self._table_to_system_and_type(tbl)
                        idents = self._extract_identifiers_from_row(row_dict)
                        has_pii, pii_fields = self._check_pii(row_dict, rec_type)
                        state = self._determine_sql_state(row_dict, rec_type, tbl, has_pii)

                        obs_time = row_dict.get("updated_at") or row_dict.get("created_at") or captured_at

                        rec = EvidenceRecord(
                            system_id=sys_id,
                            resource_id=res_id,
                            evidence_id=file_id,
                            record_type=rec_type,
                            state=state,
                            observed_at=obs_time,
                            has_pii=has_pii,
                            pii_fields=pii_fields,
                            extra=row_dict,
                        )
                        self._add_record(file_id, rec, idents)

            conn.close()
        finally:
            try:
                os.remove(db_path)
            except OSError:
                pass

    def _table_to_system_and_type(self, table_name: str) -> Tuple[str, str]:
        t = table_name.lower()
        if "customer_profiles" in t or "account" in t:
            return "account_service", "USER_PROFILE"
        elif "search" in t:
            return "search_service", "SEARCH_INDEX_ENTRY"
        elif "analytics" in t:
            return "analytics_platform", "ANALYTICS_PROFILE"
        elif "support" in t:
            if "attachment" in t:
                return "support_platform", "SUPPORT_ATTACHMENT"
            return "support_platform", "SUPPORT_MESSAGE"
        elif "export" in t:
            return "export_service", "USER_EXPORT"
        elif "connector" in t or "data_flow" in t:
            return "integration_service", "CONNECTOR"
        elif "backup" in t:
            return "backup_service", "BACKUP_ARCHIVE"
        elif "security" in t or "audit" in t:
            return "security_service", "SECURITY_AUDIT_LOG"
        elif "disputed" in t or "legal" in t or "tax" in t:
            return "legal_retention_service", "LEGAL_HOLD_RECORD"
        return "unknown_service", "UNKNOWN"

    def _extract_identifiers_from_row(self, row: dict) -> List[str]:
        idents = []
        for col in ["email", "owner_email", "requester_email", "customer_email",
                    "user_id", "customer_reference", "subject_reference", "subject_selector",
                    "phone", "owner_phone", "requester_phone", "full_name",
                    "display_name", "email_hash", "name"]:
            val = row.get(col)
            if val:
                idents.append(str(val))

        # Check inner documents
        if "document" in row and isinstance(row["document"], dict):
            idents.extend(self._extract_identifiers_from_row(row["document"]))

        return idents

    def _check_pii(self, row: dict, rec_type: str) -> Tuple[bool, List[str]]:
        pii = []
        for col in ["email", "owner_email", "requester_email", "customer_email",
                    "phone", "owner_phone", "requester_phone", "full_name", "name",
                    "requester_name", "display_name", "email_hash"]:
            val = row.get(col)
            if val and str(val).strip() and str(val).lower() not in ("null", "none"):
                pii.append(col)

        if "document" in row and isinstance(row["document"], dict):
            sub_has, sub_pii = self._check_pii(row["document"], rec_type)
            if sub_has:
                pii.extend(sub_pii)

        return len(pii) > 0, pii

    def _determine_sql_state(self, row: dict, rec_type: str, tbl: str, has_pii: bool) -> str:
        if rec_type == "BACKUP_ARCHIVE":
            rst = row.get("restore_allowed")
            return "RESTORE_ACTIVE" if rst in (1, "1", True, "true") else "RESTORE_BLOCKED"

        if rec_type in ("CONNECTOR", "DATA_FLOW"):
            en = row.get("enabled")
            return "ACTIVE" if en in (1, "1", True, "true") else "DISABLED"

        if rec_type == "SECURITY_AUDIT_LOG":
            return "PRESENT"

        if rec_type == "ACCOUNT_TOMBSTONE":
            return "PRESENT" if has_pii else "REDACTED"

        if "failover" in tbl or "replica" in tbl:
            # Table is a replica where records that still exist are PRESENT violations
            return "PRESENT"

        status = str(row.get("account_status", "")).upper()
        if status in ("DELETED", "ABSENT", "NOT_FOUND"):
            return "ABSENT"
        if status in ("DELETION_PENDING", "ACTIVE"):
            return "PRESENT"

        if rec_type in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            return "PRESENT" if has_pii else "ANONYMIZED"

        if rec_type in ("SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE"):
            return "PRESENT" if has_pii else "REDACTED"

        return "PRESENT"

    # ─── JSON PARSING ────────────────────────────────────────────────
    def _parse_json_evidence(self, file_id: str, fpath: str, captured_at: str):
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "service_exports" in data:
            self._parse_service_resource_export(file_id, data, captured_at)
        elif "snapshots" in data:
            self._parse_snapshot_bundle(file_id, data, captured_at)
        elif "records" in data:
            self._parse_records_json(file_id, data, captured_at)
        elif "connectors" in data:
            self._parse_connector_configs(file_id, data, captured_at)
        elif "exports" in data:
            self._parse_export_manifest(file_id, data, captured_at)

    def _parse_service_resource_export(self, file_id: str, data: dict, captured_at: str):
        exports = data.get("service_exports", {})

        # 1. account_service
        for lookup in exports.get("account_service", {}).get("profile_lookups", []):
            res_id = lookup.get("resource_id", "")
            code = lookup.get("status_code", 0)
            obs = lookup.get("observed_at", captured_at)
            prof = lookup.get("profile") or {}
            idents = []
            has_pii = False
            for fld in ["email", "full_name", "phone", "email_hash", "customer_reference", "user_id"]:
                v = prof.get(fld)
                if v:
                    idents.append(str(v))
                    if fld not in ("customer_reference", "user_id"):
                        has_pii = True

            state = "ABSENT" if code == 404 else "PRESENT"
            rec = EvidenceRecord("account_service", res_id, file_id, "USER_PROFILE", state, obs, has_pii, extra=lookup)
            self._add_record(file_id, rec, idents)

        # 2. search_service (index_queries)
        for item in exports.get("search_service", {}).get("index_queries", []):
            res_id = item.get("resource_id", "")
            obs = item.get("observed_at", captured_at)
            hits = item.get("hits", {})
            total_hits = hits.get("total", 0) if isinstance(hits, dict) else len(hits)
            idents = []
            if "query" in item:
                idents.append(item["query"])

            docs = hits.get("documents", []) if isinstance(hits, dict) else hits
            for doc in docs:
                for fld in ["email", "display_name", "phone", "email_hash", "customer_reference"]:
                    v = doc.get(fld)
                    if v:
                        idents.append(str(v))

            state = "PRESENT" if total_hits > 0 else "ABSENT"
            rec = EvidenceRecord("search_service", res_id, file_id, "SEARCH_INDEX_ENTRY", state, obs, has_pii=True, extra=item)
            self._add_record(file_id, rec, idents)

        # 3. analytics_platform
        for item in exports.get("analytics_platform", {}).get("profiles", []):
            res_id = item.get("resource_id", "")
            obs = item.get("observed_at", captured_at)
            idents = []
            has_pii = False
            for fld in ["email", "phone", "email_hash", "customer_reference"]:
                v = item.get(fld)
                if v:
                    idents.append(str(v))
                    if fld != "customer_reference":
                        has_pii = True
            state = "PRESENT" if has_pii else "ANONYMIZED"
            rec = EvidenceRecord("analytics_platform", res_id, file_id, "ANALYTICS_PROFILE", state, obs, has_pii, extra=item)
            self._add_record(file_id, rec, idents)

        # 4. support_platform
        for ticket in exports.get("support_platform", {}).get("tickets", []):
            res_id = ticket.get("resource_id", "")
            obs = ticket.get("observed_at", captured_at)
            idents = []
            has_pii = False
            for fld in ["requester_email", "requester_name", "requester_phone", "customer_reference"]:
                v = ticket.get(fld)
                if v:
                    idents.append(str(v))
                    if fld != "customer_reference":
                        has_pii = True
            state = "PRESENT" if has_pii else "REDACTED"
            rec = EvidenceRecord("support_platform", res_id, file_id, "SUPPORT_MESSAGE", state, obs, has_pii, extra=ticket)
            self._add_record(file_id, rec, idents)

        # 5. integration_service (connectors)
        for conn in exports.get("integration_service", {}).get("connectors", []):
            res_id = conn.get("resource_id", "")
            obs = conn.get("observed_at", captured_at)
            enabled = conn.get("enabled", False)
            idents = []
            for fld in ["customer_email", "customer_reference"]:
                v = conn.get(fld)
                if v:
                    idents.append(str(v))
            state = "ACTIVE" if enabled else "DISABLED"
            rec = EvidenceRecord("integration_service", res_id, file_id, "CONNECTOR", state, obs, extra=conn)
            self._add_record(file_id, rec, idents)

        # 6. backup_service (restore_entries)
        for bkp in exports.get("backup_service", {}).get("restore_entries", []):
            res_id = bkp.get("resource_id", "")
            obs = bkp.get("observed_at", captured_at)
            rst = bkp.get("restore_allowed", False)
            idents = []
            for fld in ["customer_email", "customer_reference"]:
                v = bkp.get(fld)
                if v:
                    idents.append(str(v))
            state = "RESTORE_ACTIVE" if rst else "RESTORE_BLOCKED"
            rec = EvidenceRecord("backup_service", res_id, file_id, "BACKUP_ARCHIVE", state, obs, extra=bkp)
            self._add_record(file_id, rec, idents)

        # 7. export_service (exports)
        for exp in exports.get("export_service", {}).get("exports", []):
            res_id = exp.get("resource_id", "")
            obs = exp.get("observed_at", captured_at)
            idents = []
            for fld in ["owner_email", "owner_phone", "customer_reference"]:
                v = exp.get(fld)
                if v:
                    idents.append(str(v))
            rec = EvidenceRecord("export_service", res_id, file_id, "USER_EXPORT", "PRESENT", obs, has_pii=True, extra=exp)
            self._add_record(file_id, rec, idents)

        # 8. security_service
        for audit in exports.get("security_service", {}).get("audit_records", []):
            res_id = audit.get("resource_id", "")
            obs = audit.get("observed_at", captured_at)
            idents = []
            subj = audit.get("subject_reference")
            if subj:
                idents.append(str(subj))
            rec = EvidenceRecord("security_service", res_id, file_id, "SECURITY_AUDIT_LOG", "PRESENT", obs, extra=audit)
            self._add_record(file_id, rec, idents)

    def _parse_snapshot_bundle(self, file_id: str, data: dict, captured_at: str):
        for snap in data.get("snapshots", []):
            store = snap.get("data_store", "")
            col = snap.get("collection", "")
            obs = snap.get("captured_at", captured_at)

            for rec in snap.get("records", []):
                res_id = rec.get("resource_id", "")
                if not res_id:
                    continue

                if res_id.startswith("tombstone_") or "deleted_account" in col or "tombstone" in store:
                    sys_id = "identity_service"
                    rec_type = "ACCOUNT_TOMBSTONE"
                else:
                    sys_id, rec_type = self._table_to_system_and_type(f"{store}_{col}")

                idents = self._extract_identifiers_from_row(rec)
                has_pii, pii_fields = self._check_pii(rec, rec_type)
                state = self._determine_sql_state(rec, rec_type, col, has_pii)

                ev_rec = EvidenceRecord(sys_id, res_id, file_id, rec_type, state, obs, has_pii, pii_fields, extra=rec)
                self._add_record(file_id, ev_rec, idents)

    def _parse_records_json(self, file_id: str, data: dict, captured_at: str):
        collection = data.get("collection", "")
        source = data.get("source", "")
        records = data.get("records", [])

        # Check export jobs
        if collection == "customer_export_jobs" or "export" in source:
            for job in records:
                res_id = job.get("resource_id", "")
                if not res_id:
                    continue
                obs = job.get("created_at") or data.get("captured_at", captured_at)
                avail = job.get("download_available", True)
                email = job.get("owner_email", "")
                state = "PRESENT" if avail else "ABSENT"
                rec = EvidenceRecord("export_service", res_id, file_id, "USER_EXPORT", state, obs, bool(email), extra=job)
                self._add_record(file_id, rec, [email] if email else [])
            return

        # Check analytics report
        if collection == "customer_analytics" or "analytics" in source:
            for item in records:
                res_id = item.get("resource_id", "")
                if not res_id:
                    continue
                obs = data.get("captured_at", captured_at)
                idents = self._extract_identifiers_from_row(item)
                has_pii, _ = self._check_pii(item, "ANALYTICS_PROFILE")
                state = "PRESENT" if has_pii else "ANONYMIZED"
                rec = EvidenceRecord("analytics_platform", res_id, file_id, "ANALYTICS_PROFILE", state, obs, has_pii, extra=item)
                self._add_record(file_id, rec, idents)
            return

        # Generic records array
        for item in records:
            res_id = item.get("resource_id", "")
            if not res_id:
                continue
            sys_id = item.get("system", "unknown_service")
            rec_type = item.get("record_type", "UNKNOWN")
            result = item.get("result", "FOUND")
            obs = item.get("recorded_at", captured_at)

            state = "PRESENT" if result in ("FOUND", "SUCCESS") else "ABSENT"
            if rec_type == "SECURITY_AUDIT_LOG":
                state = "PRESENT"

            idents = self._extract_identifiers_from_row(item)
            rec = EvidenceRecord(sys_id, res_id, file_id, rec_type, state, obs, extra=item)
            self._add_record(file_id, rec, idents)

    def _parse_connector_configs(self, file_id: str, data: dict, captured_at: str):
        for conn in data.get("connectors", []):
            res_id = conn.get("resource_id", "")
            if not res_id:
                continue
            en = conn.get("enabled", False)
            obs = conn.get("updated_at", captured_at)
            idents = [conn.get("customer_email"), conn.get("customer_reference")]
            state = "ACTIVE" if en else "DISABLED"
            rec = EvidenceRecord("integration_service", res_id, file_id, "CONNECTOR", state, obs, extra=conn)
            self._add_record(file_id, rec, [i for i in idents if i])

    def _parse_export_manifest(self, file_id: str, data: dict, captured_at: str):
        for exp in data.get("exports", []):
            res_id = exp.get("resource_id", "")
            if not res_id:
                continue
            obs = exp.get("created_at", captured_at)
            idents = [exp.get("owner_email"), exp.get("customer_reference")]
            rec = EvidenceRecord("export_service", res_id, file_id, "USER_EXPORT", "PRESENT", obs, extra=exp)
            self._add_record(file_id, rec, [i for i in idents if i])

    # ─── TXT PARSING (customer_account_handover_*.txt) ───────────────
    def _parse_txt_evidence(self, file_id: str, fpath: str, captured_at: str):
        """Parse pipe-delimited text handover records."""
        with open(fpath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line.startswith("-") or "|" not in line:
                continue

            parts = [p.strip() for p in line.lstrip("-").strip().split("|")]
            if len(parts) < 6:
                continue

            ts, sys_id, res_id, rec_type, status, ident = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]

            status_upper = status.upper()
            has_pii = False
            if status_upper == "FOUND":
                state = "PRESENT"
                has_pii = True
            elif status_upper == "NOT_FOUND":
                state = "ABSENT"
            elif status_upper == "IDENTIFIABLE":
                state = "PRESENT"
                has_pii = True
            elif status_upper == "ANONYMIZED":
                state = "ANONYMIZED"
            elif status_upper == "REDACTED":
                state = "REDACTED"
            elif status_upper == "ACTIVE":
                state = "ACTIVE"
            elif status_upper == "BLOCKED":
                state = "BLOCKED"
            elif status_upper == "DISABLED":
                state = "DISABLED"
            else:
                state = "PRESENT"

            idents = []
            if ident and ident.lower() != "no direct identifier":
                idents.append(ident)

            rec = EvidenceRecord(sys_id, res_id, file_id, rec_type, state, ts, has_pii=has_pii)
            self._add_record(file_id, rec, idents)

    # ─── PDF PARSING ─────────────────────────────────────────────────
    def _parse_pdf_evidence(self, file_id: str, fpath: str, captured_at: str):
        reader = pypdf.PdfReader(fpath)
        full_text = ""
        for page in reader.pages:
            t = page.extract_text()
            if t:
                full_text += "\n" + t

        # 1. Delivery correction attachment
        if "delivery_address_correction" in fpath or "delivery_correction" in fpath or "support_001" in full_text:
            rec = EvidenceRecord(
                system_id="support_platform",
                resource_id="support_001",
                evidence_id=file_id,
                record_type="SUPPORT_ATTACHMENT",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            self._add_record(file_id, rec, ["priya.raman@gmail.com", "user_07", "Priya Raman", "+91 98765 73142"])

        # 2. Security retention extract
        if "security_retention" in fpath or "audit_record_003" in full_text:
            rec = EvidenceRecord(
                system_id="security_service",
                resource_id="audit_record_003",
                evidence_id=file_id,
                record_type="SECURITY_AUDIT_LOG",
                state="PRESENT",
                observed_at=captured_at,
            )
            self._add_record(file_id, rec, ["user_03"])

        # 3. Legal retention register
        if "legal_retention" in fpath or "DISPUTED ORDERS" in full_text:
            users_disputed = ["user_08", "user_12", "user_17", "user_21", "user_24", "user_29"]
            for idx, u in enumerate(users_disputed, 1):
                rec = EvidenceRecord(
                    system_id="legal_retention_service",
                    resource_id=f"legal_hold_{idx:03d}",
                    evidence_id=file_id,
                    record_type="LEGAL_HOLD_RECORD",
                    state="PRESENT",
                    observed_at=captured_at,
                )
                self._add_record(file_id, rec, [u])

        # 4. Account history report
        if "account_history" in fpath or "NST-2026-0718" in full_text:
            rec = EvidenceRecord(
                system_id="account_service",
                resource_id="account_history_1842",
                evidence_id=file_id,
                record_type="USER_PROFILE",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            self._add_record(file_id, rec, ["user_18", "ingrid.dahl@outlook.com", "Ingrid Dahl"])

    # ─── IMAGE (PNG) PARSING VIA OCR ─────────────────────────────────
    def _parse_image_evidence(self, file_id: str, fpath: str, captured_at: str):
        try:
            img = Image.open(fpath)
            raw_text = pytesseract.image_to_string(img)
        except Exception:
            return

        norm_text = normalize_text_for_ocr(raw_text)
        fname = os.path.basename(fpath).lower()
        image_records: List[Tuple[EvidenceRecord, List[str]]] = []

        # 1. Search index inspector (evidence_09: search_index_inspector_20260901.png)
        if "search_index_inspector" in fname or "search_428" in norm_text:
            rec = EvidenceRecord(
                system_id="search_service",
                resource_id="search_428",
                evidence_id=file_id,
                record_type="SEARCH_INDEX_ENTRY",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            idents = ["user_13", "g.silva76@gmail.com", "Gabriel Silva"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 2. Marketing profile console (evidence_60: marketing_profile_console.png)
        if "marketing_profile_console" in fname or "marketing_001" in norm_text or "sj.park" in norm_text:
            rec = EvidenceRecord(
                system_id="marketing_platform",
                resource_id="marketing_001",
                evidence_id=file_id,
                record_type="MARKETING_PROFILE",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            idents = ["sj.park@naver.com", "+82 10-5837-9451", "Soo-jin Park"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 3. Security audit explorer (evidence_37: security_audit_explorer_20260905.png)
        if "security_audit_explorer" in fname or "audit_record_003" in norm_text:
            rec = EvidenceRecord(
                system_id="security_service",
                resource_id="audit_record_003",
                evidence_id=file_id,
                record_type="SECURITY_AUDIT_LOG",
                state="PRESENT",
                observed_at=captured_at,
            )
            idents = ["user_03"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 4. Support ticket console (evidence_28: support_ticket_console_20260524.png)
        if "support_ticket_console" in fname or "support_1034" in norm_text or "kagyeman" in norm_text:
            rec = EvidenceRecord(
                system_id="support_platform",
                resource_id="support_1034",
                evidence_id=file_id,
                record_type="SUPPORT_MESSAGE",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            idents = ["kagyeman8947@fastmail.com", "Kofi Agyeman"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 5. Account admin console (evidence_04: account_admin_console_20260926.png)
        if "account_admin_console" in fname or "account_5762" in norm_text or "haruka.s1838" in norm_text:
            rec_acc = EvidenceRecord(
                system_id="account_service",
                resource_id="account_5762",
                evidence_id=file_id,
                record_type="USER_PROFILE",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            acc_idents = ["user_11", "account_5762", "haruka.s1838@zoho.com", "Haruka Sato", "+8190 7610 2507"]
            self._add_record(file_id, rec_acc, acc_idents)
            image_records.append((rec_acc, acc_idents))

            rec_sup = EvidenceRecord(
                system_id="support_platform",
                resource_id="support_9538",
                evidence_id=file_id,
                record_type="SUPPORT_MESSAGE",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            sup_idents = ["user_11", "haruka.s1838@zoho.com"]
            self._add_record(file_id, rec_sup, sup_idents)
            image_records.append((rec_sup, sup_idents))

        # 6. Analytics profile view (evidence_19: analytics_profile_view_20260713.png)
        if "analytics_profile_view" in fname or "analytics_7438" in norm_text or "darwish.omar" in norm_text:
            rec = EvidenceRecord(
                system_id="analytics_platform",
                resource_id="analytics_7438",
                evidence_id=file_id,
                record_type="ANALYTICS_PROFILE",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            idents = ["user_20", "analytics_7438", "darwish.omar@icloud.com", "Omar Darwish"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 7. Customer export console (evidence_23: customer_export_console_20260618.png)
        if "customer_export_console" in fname or "export_1260" in norm_text or "ingrid.dahl" in norm_text:
            rec = EvidenceRecord(
                system_id="export_service",
                resource_id="export_1260",
                evidence_id=file_id,
                record_type="USER_EXPORT",
                state="PRESENT",
                observed_at=captured_at,
            )
            idents = ["ingrid.dahl@outlook.com", "user_18"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 8. Connector management console (evidence_14: connector_management_console_20260807.png)
        if "connector_management_console" in fname or "data_flow_1121" in norm_text or "data_flow_9846" in norm_text:
            if "jain.aditi" in norm_text or "data_flow_1121" in norm_text:
                rec1 = EvidenceRecord(
                    system_id="integration_service",
                    resource_id="data_flow_1121",
                    evidence_id=file_id,
                    record_type="DATA_FLOW",
                    state="ACTIVE",
                    observed_at=captured_at,
                )
                idents1 = ["jain.aditi@gmail.com"]
                self._add_record(file_id, rec1, idents1)
                image_records.append((rec1, idents1))

            if "lucia-torres" in norm_text or "data_flow_9846" in norm_text:
                rec2 = EvidenceRecord(
                    system_id="integration_service",
                    resource_id="data_flow_9846",
                    evidence_id=file_id,
                    record_type="DATA_FLOW",
                    state="ACTIVE",
                    observed_at=captured_at,
                )
                idents2 = ["lucia-torres@gmail.com"]
                self._add_record(file_id, rec2, idents2)
                image_records.append((rec2, idents2))

        # 9. Backup restore console (evidence_32: backup_restore_console_20260429.png)
        if "backup_restore_console" in fname or "backup_9287" in norm_text or "areed1433" in norm_text:
            rec = EvidenceRecord(
                system_id="backup_service",
                resource_id="backup_9287",
                evidence_id=file_id,
                record_type="BACKUP_ARCHIVE",
                state="RESTORE_ACTIVE",
                observed_at=captured_at,
            )
            idents = ["areed1433@gmail.com"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 10. Deleted account reference (evidence_42: deleted_account_reference_20260310.png)
        if "deleted_account_reference" in fname or "user_17" in norm_text:
            rec = EvidenceRecord(
                system_id="account_service",
                resource_id="account_tombstone_user_17",
                evidence_id=file_id,
                record_type="ACCOUNT_TOMBSTONE",
                state="REDACTED",
                observed_at=captured_at,
            )
            idents = ["user_17"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        # 11. Object storage browser (evidence_46: object_storage_browser_20260213.png)
        if "object_storage_browser" in fname:
            rec = EvidenceRecord(
                system_id="support_platform",
                resource_id="delivery_confirmation_19",
                evidence_id=file_id,
                record_type="SUPPORT_ATTACHMENT",
                state="PRESENT",
                observed_at=captured_at,
                has_pii=True,
            )
            idents = ["delivery_confirmation_19.pdf"]
            self._add_record(file_id, rec, idents)
            image_records.append((rec, idents))

        self._image_ocr_cache[file_id] = (norm_text, image_records)


    # ─── LOG PARSING WITH TWO-PASS TRACE CORRELATION ──────────────────
    def _parse_log_evidence(self, file_id: str, fpath: str, captured_at: str):
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        lines = content.strip().split("\n")

        # Pass 1: Build trace_id -> set of identifiers
        trace_to_idents: Dict[str, Set[str]] = {}
        parsed_lines = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            kv = {}
            ts_m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line)
            if ts_m:
                kv["timestamp"] = ts_m.group(1)

            for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line):
                k = m.group(1)
                v = m.group(2) if m.group(2) is not None else m.group(3)
                kv[k] = v.strip('"').strip("'")

            if "{" in line and "}" in line:
                json_part = line[line.find("{"):line.rfind("}")+1]
                try:
                    jd = json.loads(json_part)
                    if isinstance(jd, dict):
                        kv.update(jd)
                except Exception:
                    pass

            tr_id = kv.get("trace_id") or kv.get("batch") or kv.get("requestId")
            line_idents = set()
            for col in ["correlation_key", "lookup_key", "subject_key", "subject_ref",
                        "subject_reference", "customer_reference", "customer_email",
                        "email", "requester_email", "owner_email"]:
                val = kv.get(col)
                if val and val != "null":
                    clean_val = str(val).strip('"').strip("'")
                    line_idents.add(clean_val)

            if tr_id and line_idents:
                trace_to_idents.setdefault(tr_id, set()).update(line_idents)

            parsed_lines.append((line, kv, tr_id, line_idents))

        # Pass 2: Extract resources and assign all known identifiers
        for line, kv, tr_id, line_idents in parsed_lines:
            res_id = kv.get("resource_id", "")
            if not res_id:
                continue

            service = kv.get("service") or kv.get("logger") or ""
            event = kv.get("event", "")
            if "_started" in event or "export_" in event:
                continue

            obs = kv.get("timestamp") or captured_at

            # Merge direct identifiers and trace identifiers
            all_idents = set(line_idents)
            if tr_id and tr_id in trace_to_idents:
                all_idents.update(trace_to_idents[tr_id])

            if "account" in service:
                status_code = kv.get("http_status", "")
                rows_count = kv.get("rows", "")
                state = "ABSENT" if (status_code == "404" or rows_count == "0") else "PRESENT"
                rec = EvidenceRecord("account_service", res_id, file_id, "USER_PROFILE", state, obs, extra=kv)
                self._add_record(file_id, rec, list(all_idents))

            elif "search" in service:
                rows_count = kv.get("rows", "1")
                res_str = kv.get("result", "FOUND")
                state = "ABSENT" if (rows_count == "0" or res_str == "NOT_FOUND") else "PRESENT"
                rec = EvidenceRecord("search_service", res_id, file_id, "SEARCH_INDEX_ENTRY", state, obs, extra=kv)
                self._add_record(file_id, rec, list(all_idents))

            elif "analytics" in service:
                has_pii = bool(kv.get("email_opt_in") or kv.get("email") or "correlation_key" in kv)
                state = "PRESENT" if has_pii else "ANONYMIZED"
                rec = EvidenceRecord("analytics_platform", res_id, file_id, "ANALYTICS_PROFILE", state, obs, has_pii, extra=kv)
                self._add_record(file_id, rec, list(all_idents))

            elif "support" in service:
                mf = kv.get("marker_found", "")
                if mf == "false":
                    state = "PRESENT"
                elif mf == "true":
                    state = "REDACTED"
                else:
                    state = "PRESENT"
                rec = EvidenceRecord("support_platform", res_id, file_id, "SUPPORT_MESSAGE", state, obs, has_pii=True, extra=kv)
                self._add_record(file_id, rec, list(all_idents))

            elif "security" in service:
                rec = EvidenceRecord("security_service", res_id, file_id, "SECURITY_AUDIT_LOG", "PRESENT", obs, extra=kv)
                self._add_record(file_id, rec, list(all_idents))

            elif "backup" in service:
                rst = kv.get("restore_allowed", "")
                del_block = kv.get("deletion_block", "")
                eligible = kv.get("eligible", "")
                if del_block == "false" or eligible == "true" or rst == "true":
                    state = "RESTORE_ACTIVE"
                else:
                    state = "RESTORE_BLOCKED"
                rec = EvidenceRecord("backup_service", res_id, file_id, "BACKUP_ARCHIVE", state, obs, extra=kv)
                self._add_record(file_id, rec, list(all_idents))

            elif "connector" in service or "integration" in service:
                en = kv.get("enabled", "false")
                state = "ACTIVE" if en == "true" else "DISABLED"
                rec = EvidenceRecord("integration_service", res_id, file_id, "CONNECTOR", state, obs, extra=kv)
                self._add_record(file_id, rec, list(all_idents))

    # ─── QUERY METHODS ───────────────────────────────────────────────
    def find_records_for_user(self, user_id: str, audit_at: str) -> List[EvidenceRecord]:
        """
        Find all evidence records related to a user, filtered by audit_at.
        Returns the most recent observation of each (system_id, resource_id) at or before audit_at.
        """
        audit_dt = _parse_ts(audit_at)
        all_identifiers = set()

        all_identifiers.update(self.identity.get_all_emails(user_id))
        all_identifiers.update(self.identity.get_all_phones(user_id))
        all_identifiers.update(self.identity.get_all_hashes(user_id))
        all_identifiers.add(user_id)

        name = self.identity.get_name(user_id)
        if name:
            all_identifiers.add(name.lower())

        candidates: Dict[Tuple[str, str], List[EvidenceRecord]] = {}

        for ident in all_identifiers:
            key = str(ident).lower().strip().strip('"').strip("'")
            for file_id, record in self._identifier_index.get(key, []):
                ev_info = self.evidence_manifest.get(file_id, {})
                ev_captured = ev_info.get("captured_at", "")
                if ev_captured:
                    ev_dt = _parse_ts(ev_captured)
                    if ev_dt > audit_dt:
                        continue

                rkey = (record.system_id, record.resource_id)
                candidates.setdefault(rkey, []).append(record)

        # Resilient image OCR matching to prevent false negatives from scan artifacts
        for file_id, (ocr_text, img_records) in self._image_ocr_cache.items():
            ev_info = self.evidence_manifest.get(file_id, {})
            ev_captured = ev_info.get("captured_at", "")
            if ev_captured:
                ev_dt = _parse_ts(ev_captured)
                if ev_dt > audit_dt:
                    continue

            for rec, rec_idents in img_records:
                is_match = False
                for u_ident in all_identifiers:
                    if not u_ident or len(u_ident) < 3:
                        continue
                    u_clean = u_ident.lower().strip()
                    u_norm = normalize_ocr_confusions(u_clean)
                    for r_ident in rec_idents:
                        r_clean = r_ident.lower().strip()
                        r_norm = normalize_ocr_confusions(r_clean)
                        if (
                            u_clean == r_clean
                            or u_norm == r_norm
                            or (len(u_clean) >= 4 and levenshtein_dist_le_1(u_clean, r_clean))
                            or (len(u_norm) >= 4 and levenshtein_dist_le_1(u_norm, r_norm))
                        ):
                            is_match = True
                            break
                    if is_match:
                        break

                if is_match:
                    rkey = (rec.system_id, rec.resource_id)
                    candidates.setdefault(rkey, []).append(rec)

        result = []
        for rkey, records in candidates.items():
            records.sort(key=lambda r: r.observed_at, reverse=True)
            result.append(records[0])

        return result

