"""
main.py — Primary entry point for Ghost Data Still Exists Deletion-Audit Agent.

Executes the full pipeline:
1. Resolves identities across current snapshots and historical audit logs.
2. Audits evidence across SQL dumps, JSON records, log files, text handovers, PDFs, and OCR images.
3. Applies deletion rules and policy engine.
4. Generates ordered, compliant findings, remediation plans, and verification steps.
5. Produces root output.csv for evaluation.
"""
import os
import sys

# Ensure code/ is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from runner import main

if __name__ == "__main__":
    main()
