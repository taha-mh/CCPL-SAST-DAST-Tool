"""
Source Context Extractor Module for CCPL Web SAST Tool.

Responsibility:
1. Load normalized SAST findings from data/normalized/normalized_findings.json.
2. Read the referenced source file for each finding.
3. Extract a code snippet window (e.g. 10 lines before and after the finding lines).
4. Attach the extracted source code context to each finding object.
5. Save the enriched findings to data/normalized/findings_with_context.json.
"""

import json
import logging
from pathlib import Path

# Configure logging to print progress and warnings
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def extract_source_context(
    normalized_json_path: str = "data/normalized/normalized_findings.json",
    output_json_path: str = "data/normalized/findings_with_context.json",
    context_window: int = 10,
) -> list:
    """
    Reads normalized findings, retrieves surrounding source code lines from disk,
    and attaches the context snippet to each finding dictionary.

    :param normalized_json_path: Path to input normalized findings JSON.
    :param output_json_path: Path to output enriched findings JSON.
    :param context_window: Number of lines to extract before start_line and after end_line.
    :return: List of enriched finding dictionaries containing source code context.
    """
    input_file = Path(normalized_json_path).resolve()
    output_file = Path(output_json_path).resolve()

    if not input_file.exists():
        logger.error(f"Normalized findings file not found at: {input_file}")
        return []

    logger.info(f"Loading normalized findings from: {input_file}")
    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        findings = json.load(f)

    logger.info(f"Extracting source context for {len(findings)} findings (window (+/-{context_window} lines))...")

    # Cache opened files in memory so we don't re-read the same source file repeatedly
    file_cache = {}

    for finding in findings:
        raw_file_path = finding.get("file_path", "")
        start_line = finding.get("start_line", 1)
        end_line = finding.get("end_line", start_line)

        if not raw_file_path:
            finding["code_context"] = "No file path provided by scanner."
            finding["context_start_line"] = 0
            finding["context_end_line"] = 0
            continue

        target_file = Path(raw_file_path).resolve()

        # Read target file lines into memory (or retrieve from cache)
        if str(target_file) not in file_cache:
            if target_file.exists() and target_file.is_file():
                try:
                    with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                        file_cache[str(target_file)] = f.readlines()
                except Exception as e:
                    logger.warning(f"Could not read source file {target_file}: {e}")
                    file_cache[str(target_file)] = None
            else:
                logger.warning(f"Source file does not exist: {target_file}")
                file_cache[str(target_file)] = None

        file_lines = file_cache.get(str(target_file))

        if file_lines is None:
            finding["code_context"] = f"Source file unavailable on disk ({raw_file_path})."
            finding["context_start_line"] = 0
            finding["context_end_line"] = 0
            continue

        total_lines = len(file_lines)

        # Calculate 1-indexed boundaries for context extraction
        context_start = max(1, start_line - context_window)
        context_end = min(total_lines, end_line + context_window)

        # Slice lines array (convert 1-indexed line numbers to 0-indexed Python array indices)
        snippet_lines = file_lines[context_start - 1 : context_end]

        # Format lines with line numbers for high readability (e.g. "  42 | $user_input = $_GET['id'];")
        formatted_snippet = []
        for idx, line in enumerate(snippet_lines, start=context_start):
            is_vulnerable_line = start_line <= idx <= end_line
            marker = "->" if is_vulnerable_line else "  "
            formatted_snippet.append(f"{marker} {idx:4d} | {line.rstrip()}")

        finding["code_context"] = "\n".join(formatted_snippet)
        finding["context_start_line"] = context_start
        finding["context_end_line"] = context_end

    # Ensure output folder exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Save enriched findings with indentation for readability
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    logger.info(f"Successfully attached context to {len(findings)} findings!")
    logger.info(f"Saved enriched findings to: {output_file}")

    return findings


if __name__ == "__main__":
    print("--- Running Milestone 4: Source Context Extractor Test ---")
    results = extract_source_context()
    print(f"\nTotal Enriched Findings: {len(results)}")
    if results:
        print("\nSample Enriched Finding (First Item):")
        sample = results[0]
        print(f"ID: {sample.get('finding_id')}")
        print(f"File: {sample.get('file_path')}")
        print(f"Lines: {sample.get('start_line')}-{sample.get('end_line')}")
        print("\n--- Code Context Snippet ---")
        print(sample.get("code_context"))
