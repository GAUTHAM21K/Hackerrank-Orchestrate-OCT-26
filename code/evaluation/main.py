"""
Evaluation harness entry point.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation_harness import run_sample_evaluation

if __name__ == "__main__":
    run_sample_evaluation()
