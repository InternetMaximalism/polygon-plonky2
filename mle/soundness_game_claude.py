#!/usr/bin/env python3
"""soundnessGameClaude - iterative soundness audit for Solidity contracts via Claude CLI."""

import subprocess
import os
import re
import sys
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
CONTRACTS_DIR = os.path.join(REPO_ROOT, "contracts", "src")
GAME_DIR = os.path.join(REPO_ROOT, "soundnessgame")
MAX_ROUNDS = 10
PARALLEL_WORKERS = 6  # Number of parallel Claude CLI instances for Phase 1


def get_sol_files() -> list[str]:
    """Get all .sol files under contracts/src/ recursively."""
    files = sorted(glob.glob(os.path.join(CONTRACTS_DIR, "**", "*.sol"), recursive=True))
    return [os.path.relpath(f, REPO_ROOT) for f in files]


def run_claude(prompt: str, allow_edit: bool = False) -> str:
    """Run claude -p with the given prompt and return stdout."""
    print(f"  [claude] running... ", end="", flush=True)
    cmd = ["claude", "-p", prompt]
    if allow_edit:
        cmd += ["--allowedTools", "Edit,Read,Glob,Grep,Write,Bash"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        print(f"ERROR (exit {result.returncode})")
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}")
        return ""
    print("done")
    return result.stdout


def vol_path_for(sol_file: str) -> str:
    """Map a .sol file path to its .vol.md path in soundnessgame/."""
    stem = os.path.basename(sol_file).replace(".sol", "")
    return os.path.join(GAME_DIR, f"{stem}.vol.md")


def _discover_one(sol_file: str) -> tuple[str, str, str]:
    """Discover issues in a single .sol file. Returns (basename, status, result)."""
    basename = os.path.basename(sol_file)
    vol = vol_path_for(sol_file)
    if os.path.exists(vol):
        return (basename, "skip", "")

    prompt = (
        f"Read the file {sol_file} and find any soundness vulnerabilities or issues. "
        f"Focus on cryptographic soundness: incorrect field arithmetic, missing range checks, "
        f"wrong modular reductions, hash collision risks, proof verification bypasses, "
        f"and any logic that could allow an invalid proof to pass verification.\n\n"
        f"Report each issue as a numbered markdown section (## 1. Title, ## 2. Title, etc.) with:\n"
        f"- Description of the issue\n"
        f"- Affected code location (line numbers)\n"
        f"- Why this is a soundness concern\n"
        f"- Suggested fix\n\n"
        f"If no issues are found, respond with exactly: NO_ISSUES_FOUND"
    )
    cmd = ["claude", "-p", prompt]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    if result.returncode != 0:
        return (basename, "error", result.stderr[:500] if result.stderr else "")
    return (basename, "ok", result.stdout)


def phase_discover():
    """Phase 1: For each .sol file, ask Claude to find soundness issues (parallel)."""
    sol_files = get_sol_files()
    print(f"Scanning {len(sol_files)} Solidity files ({PARALLEL_WORKERS} workers)...\n")

    # Filter out files that already have reports
    to_scan = []
    for sol_file in sol_files:
        vol = vol_path_for(sol_file)
        if os.path.exists(vol):
            print(f"  [{os.path.basename(sol_file)}] skipping (report already exists)")
        else:
            to_scan.append(sol_file)

    if not to_scan:
        print("  All files already scanned.\n")
        return

    print(f"  Launching {len(to_scan)} parallel scans...\n")

    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        futures = {executor.submit(_discover_one, f): f for f in to_scan}
        for future in as_completed(futures):
            basename, status, result = future.result()

            if status == "skip":
                continue
            elif status == "error":
                print(f"  [{basename}] ERROR: {result}")
                continue
            elif not result.strip():
                print(f"  [{basename}] empty response, skipping")
                continue
            elif "NO_ISSUES_FOUND" in result:
                print(f"  [{basename}] no issues found")
                continue

            # Write report
            sol_file = futures[future]
            vol = vol_path_for(sol_file)
            header = f"# {basename} — Soundness Report\n\n"
            with open(vol, "w") as f:
                f.write(header + result.strip() + "\n")
            issue_count = len(re.findall(r"^## \d+\.", result, re.MULTILINE))
            print(f"  [{basename}] {issue_count} issue(s) recorded")


def parse_sections(content: str) -> list[tuple[str, str]]:
    """Split .vol.md content into (heading_line, section_body) pairs.

    Returns a list of tuples. The heading_line includes the '## N. ...' prefix.
    The first element may be a preamble (e.g. the '# filename' title) with heading_line=''.
    """
    sections: list[tuple[str, str]] = []
    current_heading = ""
    current_body_lines: list[str] = []

    for line in content.splitlines(keepends=True):
        if re.match(r"^(~~)?## \d+\.", line):
            # Save previous section
            if current_heading or current_body_lines:
                sections.append((current_heading, "".join(current_body_lines)))
            current_heading = line.rstrip("\n")
            current_body_lines = []
        else:
            current_body_lines.append(line)

    # Save last section
    if current_heading or current_body_lines:
        sections.append((current_heading, "".join(current_body_lines)))

    return sections


def get_open_issues() -> dict[str, str]:
    """Read all .vol.md files and return {filename: filtered_content} with only open issues."""
    open_issues: dict[str, str] = {}

    for vol_file in sorted(glob.glob(os.path.join(GAME_DIR, "*.vol.md"))):
        with open(vol_file) as f:
            content = f.read()

        sections = parse_sections(content)
        open_sections: list[str] = []

        for heading, body in sections:
            # Skip strikethrough sections (fixed issues)
            if heading.startswith("~~"):
                continue
            # Skip preamble (title line, etc.)
            if not heading:
                continue
            open_sections.append(heading + "\n" + body)

        if open_sections:
            basename = os.path.basename(vol_file).replace(".vol.md", ".sol")
            open_issues[basename] = "\n".join(open_sections)

    return open_issues


def build_fix_prompt(open_issues: dict[str, str]) -> str:
    """Build the prompt for Claude to fix open issues."""
    reports = ""
    for filename, content in open_issues.items():
        reports += f"\n### {filename}\n{content}\n"

    return (
        "Read the following soundness vulnerability reports and fix each issue.\n"
        "IMPORTANT: Fixes are NOT limited to Solidity files. You may need to modify "
        "any file in the repository including Rust source code under src/, "
        "test fixtures under tests/fixtures/ or contracts/test/data/, "
        "Solidity contracts under contracts/src/, or test files under contracts/test/.\n"
        "Identify the root cause and fix it wherever it lives.\n\n"
        "For each issue you fix, output a line in exactly this format:\n"
        "FIXED: <filename> ## <number>\n"
        "For example: FIXED: GoldilocksField.sol ## 1\n\n"
        "If you cannot fix an issue or disagree that it is a real issue, output:\n"
        "SKIPPED: <filename> ## <number> — <reason>\n\n"
        f"<reports>{reports}</reports>"
    )


def mark_fixed(vol_file: str, issue_num: int, round_num: int):
    """Add strikethrough to a fixed issue's heading in the .vol.md file."""
    with open(vol_file) as f:
        content = f.read()

    pattern = rf"^(## {issue_num}\..*)$"
    replacement = rf"~~\1~~\n> Fixed in round {round_num}"

    new_content, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count > 0:
        with open(vol_file, "w") as f:
            f.write(new_content)


def mark_skipped(vol_file: str, issue_num: int, round_num: int, reason: str):
    """Add strikethrough to a skipped issue (not a real issue)."""
    with open(vol_file) as f:
        content = f.read()

    pattern = rf"^(## {issue_num}\..*)$"
    replacement = rf"~~\1~~\n> Skipped in round {round_num}: {reason}"

    new_content, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count > 0:
        with open(vol_file, "w") as f:
            f.write(new_content)


def phase_fix(round_num: int) -> bool:
    """Phase 2: Ask Claude to fix all open issues. Returns True if there was work to do."""
    open_issues = get_open_issues()
    if not open_issues:
        return False

    total = sum(len(re.findall(r"^## \d+\.", v, re.MULTILINE)) for v in open_issues.values())
    files = ", ".join(open_issues.keys())
    print(f"  {total} open issue(s) across: {files}")

    prompt = build_fix_prompt(open_issues)
    result = run_claude(prompt, allow_edit=True)

    if not result.strip():
        print("  -> empty response from Claude")
        return True

    # Parse FIXED: and SKIPPED: lines (tolerant of markdown bold ** wrappers)
    fixed_count = 0
    for match in re.finditer(r"^\*{0,2}FIXED:\s*(\S+\.sol)\s*##\s*(\d+)\*{0,2}", result, re.MULTILINE):
        filename = match.group(1)
        issue_num = int(match.group(2))
        stem = filename.replace(".sol", "")
        vol_file = os.path.join(GAME_DIR, f"{stem}.vol.md")
        if os.path.exists(vol_file):
            mark_fixed(vol_file, issue_num, round_num)
            fixed_count += 1
            print(f"    -> marked {filename} ## {issue_num} as fixed")

    for match in re.finditer(r"^\*{0,2}SKIPPED:\s*(\S+\.sol)\s*##\s*(\d+)\*{0,2}\s*[—-]\s*(.+)$", result, re.MULTILINE):
        filename = match.group(1)
        issue_num = int(match.group(2))
        reason = match.group(3).strip()
        stem = filename.replace(".sol", "")
        vol_file = os.path.join(GAME_DIR, f"{stem}.vol.md")
        if os.path.exists(vol_file):
            mark_skipped(vol_file, issue_num, round_num, reason)
            fixed_count += 1
            print(f"    -> marked {filename} ## {issue_num} as skipped: {reason}")

    if fixed_count == 0:
        print("  -> no FIXED/SKIPPED markers found in Claude output")
        print("  -> raw output (first 500 chars):")
        print(result[:500])

    return True


def print_summary():
    """Print final summary of all .vol.md files."""
    print("\n=== Summary ===\n")
    for vol_file in sorted(glob.glob(os.path.join(GAME_DIR, "*.vol.md"))):
        basename = os.path.basename(vol_file)
        with open(vol_file) as f:
            content = f.read()

        total = len(re.findall(r"^(~~)?## \d+\.", content, re.MULTILINE))
        fixed = len(re.findall(r"^~~## \d+\.", content, re.MULTILINE))
        remaining = total - fixed
        status = "CLEAR" if remaining == 0 else f"{remaining} open"
        print(f"  {basename}: {total} issues, {fixed} fixed — {status}")


def main():
    os.makedirs(GAME_DIR, exist_ok=True)

    print("=" * 60)
    print("  soundnessGameClaude — Iterative Soundness Audit")
    print("=" * 60)

    print("\n=== Phase 1: Discovering soundness issues ===\n")
    phase_discover()

    for round_num in range(1, MAX_ROUNDS + 1):
        open_issues = get_open_issues()
        if not open_issues:
            print(f"\n=== All issues resolved! ===\n")
            break

        print(f"\n=== Fix round {round_num}/{MAX_ROUNDS} ===\n")
        phase_fix(round_num)
    else:
        print(f"\nReached max rounds ({MAX_ROUNDS}). Some issues may remain open.")

    print_summary()


if __name__ == "__main__":
    main()
