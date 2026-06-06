from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(
    filename,
    stats,
    top_file
):

    pdf = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "HashGuard Security Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Security Event Statistics",
            styles["Heading2"]
        )
    )

    for stat in stats:

        content.append(
            Paragraph(
                f"{stat[0]} : {stat[1]} events",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 15))

    if top_file:

        content.append(
            Paragraph(
                f"Most Targeted File: {top_file[0]} ({top_file[1]} alerts)",
                styles["BodyText"]
            )
        )

    pdf.build(content)