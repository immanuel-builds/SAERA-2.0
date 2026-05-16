"""
PDF Report Generator using ReportLab
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
from django.conf import settings
import os
from ..models import Report


def generate_pdf_report(scan_job, user):
    """
    Generate a PDF report for a completed scan
    """
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"saera_report_{scan_job.id}_{timestamp}.pdf"
    filepath = os.path.join(reports_dir, filename)
    
    # Sumi-e Palette
    INK = colors.HexColor('#1A1A1A')
    SEAL = colors.HexColor('#9F3B32')
    BAMBOO = colors.HexColor('#4E6B57')
    ASH = colors.HexColor('#6B6B6B')
    PARCHMENT = colors.HexColor('#EAE2D6')

    # Create PDF document
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=26,
        textColor=INK,
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=18,
        textColor=INK,
        spaceAfter=15,
        borderPadding=5,
        fontName='Helvetica-Bold'
    )

    subheading_style = ParagraphStyle(
        'SubHeading',
        parent=styles['Normal'],
        fontSize=10,
        textColor=ASH,
        alignment=TA_CENTER,
        spaceAfter=20,
        fontName='Helvetica-Oblique'
    )
    
    # Header: SAERA Branding
    story.append(Paragraph("SAERA: SILENT OBSERVATORY", title_style))
    story.append(Paragraph("INTELLIGENCE CHRONICLE", subheading_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    
    # Calculate aggregate risk for summary
    from django.db.models import Avg
    avg_risk = scan_job.vulnerabilities.aggregate(avg=Avg('risk_score'))['avg'] or 0
    
    summary_data = [
        ['Target Designation:', scan_job.target.name],
        ['Coordinates (IP):', scan_job.target.target],
        ['Observation Date:', scan_job.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ['Environmental Risk:', f"{avg_risk:.1f} / 10.0"],
        ['Total Findings:', str(scan_job.vulnerabilities_found)],
        ['Critical Anomalies:', str(scan_job.critical_vulns)],
        ['High Risk Alerts:', str(scan_job.high_vulns)],
    ]
    
    summary_table = Table(summary_data, colWidths=[2.2*inch, 3.8*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F5F5F5')),
        ('TEXTCOLOR', (0, 0), (-1, -1), INK),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, ASH),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 0.4*inch))
    
    # Vulnerability Findings
    story.append(Paragraph("Intelligence Archive", heading_style))
    
    vulnerabilities = scan_job.vulnerabilities.all().order_by('-severity', '-risk_score')
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            # Severity color mapping
            sev_color = BAMBOO
            if vuln.severity == 'critical': sev_color = SEAL
            elif vuln.severity == 'high': sev_color = colors.HexColor('#CC6600')
            elif vuln.severity == 'medium': sev_color = ASH
            
            vuln_data = [
                [Paragraph(f"<b>[{vuln.severity.upper()}] {vuln.title}</b>", styles['Normal'])],
                [Paragraph(f"<b>Risk Score:</b> {vuln.risk_score:.1f} | <b>Exploitability:</b> {vuln.exploitability}/10", styles['Normal'])],
                [Paragraph(f"<b>Location:</b> {vuln.port if vuln.port else 'Network'}/{vuln.protocol if vuln.protocol else 'Any'} ({vuln.service if vuln.service else 'Unknown'})", styles['Normal'])],
                [Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal'])],
                [Paragraph(f"<b>Remediation Recommendation:</b>", styles['Normal'])],
                [Paragraph(f"{vuln.recommendation}", styles['Normal'])],
            ]
            
            if vuln.cve_id:
                vuln_data.insert(2, [Paragraph(f"<b>CVE Reference:</b> {vuln.cve_id}", styles['Normal'])])
            
            vuln_table = Table(vuln_data, colWidths=[6.2*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), sev_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOX', (0, 0), (-1, -1), 1, INK),
                ('ROWBACKGROUNDS', (0, 1), (0, -1), [colors.white, colors.HexColor('#FAFAFA')]),
            ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 0.25*inch))
    else:
        story.append(Paragraph("The observation remains clear. No vulnerabilities recorded.", styles['Normal']))
    
    # Footer: System Note
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("Generated by SAERA Prediction Engine. Unauthorized duplication is recorded in the persistent chronicle.", 
                 ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7, textColor=ASH, alignment=TA_CENTER)))

    # Build PDF
    doc.build(story)
    
    # Save report to database
    report = Report.objects.create(
        scan_job=scan_job,
        title=f"Intelligence Report - {scan_job.target.name}",
        format='pdf',
        file_path=filepath,
        file_size=os.path.getsize(filepath),
        generated_by=user,
        executive_summary=f"Analysis of {scan_job.target.name} determined an aggregate risk level of {avg_risk:.1f}.",
        total_findings=scan_job.vulnerabilities_found,
    )
    
    return filepath
