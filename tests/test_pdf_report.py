import pytest

from reportlab.lib.pagesizes import landscape, letter

from src.pdf_report import (
    PAGE_LEFT,
    PAGE_RIGHT,
    PAGE_SIZE,
    TABLE_WIDTHS,
    _display_timestamp,
    generate_pdf_report,
)


def test_event_table_uses_full_wide_landscape_page():
    assert PAGE_SIZE[0] > landscape(letter)[0]
    assert sum(TABLE_WIDTHS) == pytest.approx(
        PAGE_SIZE[0] - PAGE_LEFT - PAGE_RIGHT
    )


def test_iso_timestamps_are_compact_and_readable():
    assert _display_timestamp("2026-10-30T09:13:46.727712Z") == (
        "2026-10-30 09:13:46 UTC"
    )


def test_generated_pdf_is_branded_and_contains_event_report(tmp_path):
    report_path = tmp_path / "HashGuard_Security_Report.pdf"
    events = [
        (
            "2026-10-30T09:30:00+00:00",
            "CRITICAL",
            "MODIFIED",
            "watched/config & keys.ini",
            "acknowledged",
            "analyst",
            "2026-10-30T09:35:00+00:00",
            7,
            "reviewer",
            "Signature mismatch <approved for investigation>",
        )
    ]

    generate_pdf_report(
        report_path,
        [("CRITICAL", 1)],
        ("watched/config & keys.ini", 1),
        events,
    )

    pdf_content = report_path.read_bytes()
    assert pdf_content.startswith(b"%PDF-")
    assert len(pdf_content) > 1000


def test_generated_pdf_handles_empty_event_history(tmp_path):
    report_path = tmp_path / "empty-report.pdf"

    generate_pdf_report(report_path, [], None)

    assert report_path.read_bytes().startswith(b"%PDF-")
