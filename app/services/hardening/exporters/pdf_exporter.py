import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.services.hardening.models import AuditReport
from .base import BaseReportExporter


class PDFReportExporter(BaseReportExporter):
    def export(self, report: AuditReport) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0F172A"),
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        )
        cell_style = ParagraphStyle(
            "CellText",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1E293B"),
        )
        cell_header_style = ParagraphStyle(
            "CellHeader",
            parent=styles["Normal"],
            fontSize=9,
            leading=11,
            textColor=colors.whitesmoke,
        )

        elements = []

        # Título y Cabecera
        elements.append(Paragraph("Reporte Ejecutivo de Hardening", title_style))
        elements.append(
            Paragraph(f"ID Evaluación: {report.id}", subtitle_style)
        )
        elements.append(
            Paragraph(
                f"Fecha de Ejecución: {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
                subtitle_style,
            )
        )
        elements.append(Spacer(1, 12))

        # Resumen Métricas
        summary_data = [
            [
                Paragraph("<b>Puntaje de Cumplimiento</b>", cell_style),
                Paragraph("<b>Cumplidas</b>", cell_style),
                Paragraph("<b>Fallidas</b>", cell_style),
                Paragraph("<b>No Aplica</b>", cell_style),
            ],
            [
                Paragraph(f"{getattr(report, 'score', 0.0):.1f}%", cell_style),
                Paragraph(str(getattr(report, "total_passed", 0)), cell_style),
                Paragraph(str(getattr(report, "total_failed", 0)), cell_style),
                Paragraph(
                    str(getattr(report, "total_not_applicable", 0)), cell_style
                ),
            ],
        ]
        summary_table = Table(summary_data, colWidths=[130, 100, 100, 100])
        summary_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#F1F5F9"),
                    ),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ]
            )
        )
        elements.append(summary_table)
        elements.append(Spacer(1, 16))

        # Tabla de Hallazgos
        findings = getattr(report, "findings", []) or []
        findings_data = [
            [
                Paragraph("<b>Regla</b>", cell_header_style),
                Paragraph("<b>Estado</b>", cell_header_style),
                Paragraph("<b>Severidad</b>", cell_header_style),
                Paragraph("<b>Puntaje</b>", cell_header_style),
                Paragraph("<b>Razón / Evidencia</b>", cell_header_style),
            ]
        ]

        for f in findings:
            status_val = (
                f.status.value if hasattr(f.status, "value") else str(f.status)
            )
            severity_val = (
                f.severity.value
                if hasattr(f.severity, "value")
                else str(f.severity)
            )
            score_val = f"{getattr(f, 'compliance_score', 0.0):.1f}%"
            reason_val = f.reason or f.raw_evidence or "N/A"

            findings_data.append(
                [
                    Paragraph(str(f.rule_id), cell_style),
                    Paragraph(status_val, cell_style),
                    Paragraph(severity_val, cell_style),
                    Paragraph(score_val, cell_style),
                    Paragraph(reason_val[:120], cell_style),
                ]
            )

        findings_table = Table(
            findings_data, colWidths=[80, 75, 75, 60, 250]
        )
        findings_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#0F172A"),
                    ),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ]
            )
        )
        elements.append(findings_table)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()