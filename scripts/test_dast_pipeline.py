import os
import sys
import json
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from llm.assessor import run_llm_assessor
from llm.reviewer import run_llm_reviewer

def main():
    print("--- Running DAST LLM Pipeline Test (Assessor + Reviewer) ---")
    
    # 1. Run Assessor on normalized DAST findings
    print("\n[Step 1] Running LLM Assessor...")
    assessed = run_llm_assessor(
        input_json_path="data/normalized/dast_normalized.json",
        output_json_path="data/normalized/dast_assessed.json",
        max_findings=None  # Process all 3 findings
    )
    print(f"Assessed {len(assessed)} findings.")

    # 2. Run Reviewer on assessed DAST findings
    print("\n[Step 2] Running LLM Reviewer...")
    reviewed = run_llm_reviewer(
        input_json_path="data/normalized/dast_assessed.json",
        output_json_path="data/normalized/dast_reviewed.json",
        max_findings=None
    )
    print(f"Reviewed {len(reviewed)} findings.")
    
    print("\n--- Pipeline Run Completed ---")
    for f in reviewed:
        print(f"\nID: {f.get('finding_id')}")
        print(f"Vulnerability: {f.get('vulnerability_type')}")
        print(f"Assessor Plausible: {f.get('llm_assessment', {}).get('is_plausible')}")
        print(f"Reviewer Decision: {f.get('llm_review', {}).get('decision')}")
        print(f"Reviewer Reason: {f.get('llm_review', {}).get('review_reason')}")

if __name__ == "__main__":
    # Ensure local model environment is set correctly
    if "OLLAMA_MODEL" not in os.environ:
        os.environ["OLLAMA_MODEL"] = "qwen3:8b"
    main()
