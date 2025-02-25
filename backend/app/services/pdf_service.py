from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
import json
import os

def generate_pdf(audit_id, audit_results):
    pdf_filename = f"downloads/audit_{audit_id}.pdf"
    os.makedirs("downloads", exist_ok=True)

    c = canvas.Canvas(pdf_filename, pagesize=letter)
    c.setFont("Helvetica", 10)
    c.drawString(100, 750, f"Rapport d'Audit - ID: {audit_id}")

    y_position = 730

    for key, value in audit_results.items():
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, y_position, f"{key}:")
        y_position -= 15
        c.setFont("Helvetica", 10)

        text_data = json.dumps(value, indent=2, ensure_ascii=False)  # Plus lisible

        # Gérer l'affichage des longues lignes
        for line in simpleSplit(text_data, "Helvetica", 10, 400):
            c.drawString(120, y_position, line)
            y_position -= 15
            if y_position < 50:
                c.showPage()
                y_position = 750

    c.save()
    return pdf_filename