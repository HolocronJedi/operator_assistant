from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable


class Category(str, Enum):
    SAFE = "safe"
    APPLICATION = "application"
    POTENTIALLY_UNSAFE = "potentially_unsafe"
    UNSAFE = "unsafe"


COLOR_MAP = {
    Category.SAFE: "\033[92m",  # Green
    Category.APPLICATION: "\033[94m",  # Blue
    Category.POTENTIALLY_UNSAFE: "\033[93m",  # Yellow
    Category.UNSAFE: "\033[91m",  # Red
}
RESET = "\033[0m"


@dataclass(slots=True)
class ProcessRecord:
    pid: str
    name: str
    command: str


@dataclass(slots=True)
class ClassifiedProcess:
    process: ProcessRecord
    category: Category
    reason: str


AiClassifier = Callable[[ProcessRecord], Category | None]


SUSPICIOUS_PATTERNS = [
    re.compile(r"powershell.+-enc", re.IGNORECASE),
    re.compile(r"(?:/tmp/|\\\\temp\\\\)", re.IGNORECASE),
    re.compile(r"mimikatz", re.IGNORECASE),
    re.compile(r"(?:curl|wget).+\|\s*(?:bash|sh)", re.IGNORECASE),
]


def load_name_set(file_path: str | None) -> set[str]:
    if not file_path:
        return set()
    content = Path(file_path).read_text(encoding="utf-8").strip()
    if not content:
        return set()
    data = json.loads(content)
    if not isinstance(data, list):
        raise ValueError(f"Expected list in {file_path}")
    return {str(item).lower() for item in data}


def parse_process_list(raw: str, platform: str) -> list[ProcessRecord]:
    platform = platform.lower()
    if platform == "linux":
        return _parse_linux(raw)
    if platform == "windows":
        return _parse_windows(raw)
    raise ValueError("platform must be linux or windows")


def _parse_linux(raw: str) -> list[ProcessRecord]:
    lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return []

    records: list[ProcessRecord] = []
    for line in lines[1:]:  # Skip header
        parts = line.split(maxsplit=2)
        if len(parts) < 2:
            continue
        pid = parts[0]
        name = parts[1]
        command = parts[2] if len(parts) > 2 else name
        records.append(ProcessRecord(pid=pid, name=name, command=command))
    return records


def _parse_windows(raw: str) -> list[ProcessRecord]:
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return []

    # Support csv output from: tasklist /fo csv /nh
    if lines[0].startswith('"'):
        reader = csv.reader(lines)
        records = []
        for row in reader:
            if len(row) < 2:
                continue
            name = row[0]
            pid = row[1]
            records.append(ProcessRecord(pid=pid, name=name, command=name))
        return records

    # Fallback: whitespace table from tasklist
    records: list[ProcessRecord] = []
    for line in lines[3:]:
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 2:
            continue
        name, pid = parts[0], parts[1]
        records.append(ProcessRecord(pid=pid, name=name, command=name))
    return records


def classify_processes(
    processes: Iterable[ProcessRecord],
    safe_names: set[str],
    application_names: set[str],
    unsafe_names: set[str],
    ai_classifier: AiClassifier | None = None,
) -> list[ClassifiedProcess]:
    results: list[ClassifiedProcess] = []

    for process in processes:
        lowered_name = process.name.lower()
        command = process.command.lower()

        if lowered_name in unsafe_names:
            results.append(ClassifiedProcess(process, Category.UNSAFE, "Found in known unsafe list"))
            continue

        if any(pattern.search(command) for pattern in SUSPICIOUS_PATTERNS):
            results.append(ClassifiedProcess(process, Category.UNSAFE, "Matched suspicious command pattern"))
            continue

        if lowered_name in safe_names:
            results.append(ClassifiedProcess(process, Category.SAFE, "Found in known safe list"))
            continue

        if lowered_name in application_names:
            results.append(ClassifiedProcess(process, Category.APPLICATION, "Matched installed application process"))
            continue

        if ai_classifier:
            ai_result = ai_classifier(process)
            if ai_result:
                reason = "Categorized by AI classifier"
                results.append(ClassifiedProcess(process, ai_result, reason))
                continue

        results.append(
            ClassifiedProcess(process, Category.POTENTIALLY_UNSAFE, "Unknown process; requires review")
        )

    return results


def format_report(processes: Iterable[ClassifiedProcess], use_color: bool = True) -> str:
    rows = [f"{'PID':<8} {'NAME':<30} {'CATEGORY':<20} REASON"]
    rows.append("-" * 90)

    for item in processes:
        color = COLOR_MAP[item.category] if use_color else ""
        reset = RESET if use_color else ""
        category_label = item.category.value
        row = (
            f"{item.process.pid:<8} {item.process.name:<30} "
            f"{color}{category_label:<20}{reset} {item.reason}"
        )
        rows.append(row)

    return "\n".join(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Classify Linux or Windows process lists into safe, application, potentially unsafe, and unsafe."
        )
    )
    parser.add_argument("--platform", required=True, choices=["linux", "windows"])
    parser.add_argument("--input", required=True, help="Path to a process list file")
    parser.add_argument("--safe-list", help="JSON file with safe process names")
    parser.add_argument("--application-list", help="JSON file with installed application process names")
    parser.add_argument("--unsafe-list", help="JSON file with unsafe process names")
    parser.add_argument("--no-color", action="store_true", help="Disable colorized output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    raw = Path(args.input).read_text(encoding="utf-8")
    processes = parse_process_list(raw, args.platform)

    safe_names = load_name_set(args.safe_list)
    application_names = load_name_set(args.application_list)
    unsafe_names = load_name_set(args.unsafe_list)

    classified = classify_processes(
        processes=processes,
        safe_names=safe_names,
        application_names=application_names,
        unsafe_names=unsafe_names,
    )

    print(format_report(classified, use_color=not args.no_color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
