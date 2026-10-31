"""PDF report generation for HashGuard security events."""

import os
from collections.abc import Iterable
from os import PathLike

from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import landscape, legal
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.event_status import EventStatus


NAVY = colors.HexColor("#101a28")
NAVY_LIGHT = colors.HexColor("#19283a")
CYAN = colors.HexColor("#28c8d2")
TEXT = colors.HexColor("#172334")
MUTED = colors.HexColor("#607184")
PALE = colors.HexColor("#f1f5f8")
GRID = colors.HexColor("#dce4eb")
WHITE = colors.white
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#a83245"),
    "HIGH": colors.HexColor("#c04d48"),
    "MEDIUM": colors.HexColor("#98701b"),
    "LOW": colors.HexColor("#287653"),
}
PAGE_SIZE = landscape(legal)
PAGE_WIDTH, PAGE_HEIGHT = PAGE_SIZE
PAGE_LEFT = 0.48 * inch
PAGE_RIGHT = 0.48 * inch
TABLE_WIDTH = PAGE_WIDTH - PAGE_LEFT - PAGE_RIGHT
TABLE_WIDTHS = [TABLE_WIDTH * share for share in (
    0.10,
    0.06,
    0.09,
    0.16,
    0.08,
    0.10,
    0.11,
    0.08,
    0.22,
)]


def _text(value):

    return escape(str(value if value is not None else ""))


def _paragraph(value, style):

    return Paragraph(_text(value) or "—", style)


def _display_timestamp(value):

    if value is None:

        return "—"

    try:

        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    except ValueError:

        return str(value)

    if timestamp.tzinfo is None:

        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _draw_page_chrome(canvas, document):

    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_HEIGHT - 32, PAGE_WIDTH, 32, fill=1, stroke=0)

    canvas.setFillColor(CYAN)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(PAGE_LEFT, PAGE_HEIGHT - 21, "HASHGUARD")

    canvas.setFillColor(colors.HexColor("#d7e3ed"))
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        PAGE_WIDTH - PAGE_RIGHT,
        PAGE_HEIGHT - 20,
        "FILE INTEGRITY MONITORING  /  SECURITY REPORT",
    )

    canvas.setStrokeColor(GRID)
    canvas.setLineWidth(0.6)
    canvas.line(PAGE_LEFT, 30, PAGE_WIDTH - PAGE_RIGHT, 30)

    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(PAGE_LEFT, 18, "CONFIDENTIAL - INTERNAL SECURITY RECORD")
    canvas.drawRightString(
        PAGE_WIDTH - PAGE_RIGHT,
        18,
        f"Page {document.page}",
    )
    canvas.restoreState()


def _make_styles():

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=27,
        alignment=TA_LEFT,
        textColor=NAVY,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        textColor=MUTED,
    ))
    styles.add(ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=NAVY,
        spaceBefore=9,
        spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="MetricLabel",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
        textColor=MUTED,
        uppercase=True,
    ))
    styles.add(ParagraphStyle(
        name="MetricValue",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=20,
        textColor=NAVY,
    ))
    styles.add(ParagraphStyle(
        name="TableHead",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=WHITE,
    ))
    styles.add(ParagraphStyle(
        name="TableCell",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=9.5,
        textColor=TEXT,
    ))
    styles.add(ParagraphStyle(
        name="SmallMuted",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=MUTED,
    ))
    styles.add(ParagraphStyle(
        name="RightMeta",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        alignment=TA_RIGHT,
        textColor=MUTED,
    ))

    return styles


def _summary_cards(events, stats, top_file, styles):

    total_events = len(events)
    open_events = sum(
        1 for event in events if event[4] == EventStatus.OPEN.value
    )
    critical_events = sum(
        1 for event in events if str(event[1]).upper() == "CRITICAL"
    )
    top_file_label = top_file[0] if top_file else "No file events"
    top_file_count = top_file[1] if top_file else 0
    metrics = [
        ("TOTAL EVENTS", total_events),
        ("OPEN EVENTS", open_events),
        ("CRITICAL EVENTS", critical_events),
        ("MOST TARGETED FILE", f"{top_file_label} ({top_file_count})"),
    ]

    cards = [[
        [
            Paragraph(_text(label), styles["MetricLabel"]),
            Spacer(1, 4),
            Paragraph(_text(value), styles["MetricValue"]),
        ]
        for label, value in metrics
    ]]

    table = Table(cards, colWidths=[(PAGE_WIDTH - PAGE_LEFT - PAGE_RIGHT) / 4] * 4)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.6, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, GRID),
        ("LINEBEFORE", (0, 0), (0, -1), 2, CYAN),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))

    severity_rows = [[
        Paragraph("SEVERITY", styles["TableHead"]),
        Paragraph("EVENTS", styles["TableHead"]),
    ]]
    for severity, count in sorted(
        stats,
        key=lambda item: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(str(item[0]).upper())
            if str(item[0]).upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            else 4,
            str(item[0]),
        ),
    ):
        severity_rows.append([
            Paragraph(_text(severity), styles["TableCell"]),
            Paragraph(_text(count), styles["TableCell"]),
        ])

    severity_table = Table(
        severity_rows,
        colWidths=[1.35 * inch, 0.75 * inch],
        hAlign="LEFT",
    )
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE]),
        ("BOX", (0, 0), (-1, -1), 0.5, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, GRID),
        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    return table, severity_table


def _event_table(events, styles):

    headings = [
        "TIMESTAMP",
        "SEVERITY",
        "EVENT TYPE",
        "FILE",
        "STATUS",
        "CHANGED BY",
        "CHANGED AT",
        "ACTOR",
        "EVENT DETAILS",
    ]
    rows = [[Paragraph(_text(heading), styles["TableHead"]) for heading in headings]]

    for event in events:
        rows.append([
            _paragraph(_display_timestamp(event[0]), styles["TableCell"]),
            _paragraph(event[1], styles["TableCell"]),
            _paragraph(event[2], styles["TableCell"]),
            _paragraph(event[3], styles["TableCell"]),
            _paragraph(str(event[4]).replace("_", " "), styles["TableCell"]),
            _paragraph(event[5], styles["TableCell"]),
            _paragraph(_display_timestamp(event[6]), styles["TableCell"]),
            _paragraph(event[8], styles["TableCell"]),
            _paragraph(event[9], styles["TableCell"]),
        ])

    table = Table(
        rows,
        colWidths=TABLE_WIDTHS,
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1,
    )
    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    for row_index, event in enumerate(events, start=1):
        severity = str(event[1]).upper()
        severity_color = SEVERITY_COLORS.get(severity)
        if severity_color:
            table_style.extend([
                ("TEXTCOLOR", (1, row_index), (1, row_index), severity_color),
                ("FONTNAME", (1, row_index), (1, row_index), "Helvetica-Bold"),
            ])

    table.setStyle(TableStyle(table_style))

    return table


def generate_pdf_report(
    filename: str | PathLike[str],
    stats: Iterable[tuple[str, int]],
    top_file: tuple[str, int] | None,
    events: Iterable[tuple[object, ...]] = (),
) -> None:

    events = list(events)
    styles = _make_styles()
    pdf = SimpleDocTemplate(
        os.fspath(filename),
        pagesize=PAGE_SIZE,
        rightMargin=PAGE_RIGHT,
        leftMargin=PAGE_LEFT,
        topMargin=0.62 * inch,
        bottomMargin=0.55 * inch,
        title="HashGuard Security Report",
        author="HashGuard",
        subject="File integrity monitoring event report",
    )

    summary_table, severity_table = _summary_cards(
        events,
        stats,
        top_file,
        styles,
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    content = [
        Paragraph("Security report", styles["ReportTitle"]),
        Paragraph(
            "File integrity events and triage status for your HashGuard workspace.",
            styles["ReportSubtitle"],
        ),
        Spacer(1, 5),
        Paragraph(f"Generated {generated_at}", styles["RightMeta"]),
        Spacer(1, 11),
        summary_table,
        Spacer(1, 12),
        Paragraph("Severity breakdown", styles["SectionTitle"]),
    ]

    if stats:
        content.append(severity_table)
    else:
        content.append(Paragraph("No severity counts recorded.", styles["SmallMuted"]))

    content.extend([
        Spacer(1, 9),
        Paragraph("Security events", styles["SectionTitle"]),
    ])

    if events:
        content.append(_event_table(events, styles))
    else:
        content.append(Paragraph(
            "No security events have been recorded.",
            styles["SmallMuted"],
        ))

    pdf.build(
        content,
        onFirstPage=_draw_page_chrome,
        onLaterPages=_draw_page_chrome,
    )
