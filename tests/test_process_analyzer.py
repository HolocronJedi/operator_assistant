from process_analyzer import (
    Category,
    ProcessRecord,
    classify_processes,
    format_report,
    parse_process_list,
)


def test_parse_linux_process_list():
    raw = """PID COMMAND         ARGS
1 systemd         /usr/lib/systemd/systemd
2 bash            -bash
"""
    parsed = parse_process_list(raw, "linux")

    assert len(parsed) == 2
    assert parsed[0].pid == "1"
    assert parsed[0].name == "systemd"


def test_parse_windows_csv_process_list():
    raw = '"chrome.exe","1234","Console","1","100,000 K"\n"svchost.exe","456","Services","0","10,000 K"\n'
    parsed = parse_process_list(raw, "windows")

    assert len(parsed) == 2
    assert parsed[1].name == "svchost.exe"


def test_classification_order_and_colors():
    processes = [
        ProcessRecord(pid="1", name="systemd", command="/usr/lib/systemd/systemd"),
        ProcessRecord(pid="2", name="chrome.exe", command="chrome.exe"),
        ProcessRecord(pid="3", name="evil.exe", command="evil.exe"),
        ProcessRecord(pid="4", name="unknown", command="python /tmp/payload.py"),
        ProcessRecord(pid="5", name="mystery", command="mystery --flag"),
    ]

    result = classify_processes(
        processes,
        safe_names={"systemd"},
        application_names={"chrome.exe"},
        unsafe_names={"evil.exe"},
    )

    assert [item.category for item in result] == [
        Category.SAFE,
        Category.APPLICATION,
        Category.UNSAFE,
        Category.UNSAFE,
        Category.POTENTIALLY_UNSAFE,
    ]

    report = format_report(result)
    assert "\033[92m" in report
    assert "\033[94m" in report
    assert "\033[93m" in report
    assert "\033[91m" in report
