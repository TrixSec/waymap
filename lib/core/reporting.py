#!/usr/bin/env python3
"""
Advanced Reporting System for Waymap
Generates HTML, PDF, CSV, and Markdown reports
"""

import json
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from lib.core.logger import get_logger
from lib.ui import print_status

logger = get_logger(__name__)


class ReportGenerator:
    """Generate various report formats from scan results"""
    
    def __init__(self, scan_results: Dict[str, Any]):
        """
        Initialize report generator
        
        Args:
            scan_results: Dictionary containing scan results
        """
        self.scan_results = scan_results
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
    def generate_html_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate HTML report with charts and styling
        
        Args:
            output_path: Optional custom output path
            
        Returns:
            Path to generated HTML file
        """
        if output_path is None:
            output_path = f"waymap_report_{self.timestamp}.html"
            
        try:
            html_content = self._build_html_report()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            logger.info(f"HTML report generated: {output_path}")
            print_status(f"HTML report saved: {output_path}", "success")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            print_status(f"Error generating HTML report: {e}", "error")
            raise
            
    def generate_csv_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate CSV report for spreadsheet analysis
        
        Args:
            output_path: Optional custom output path
            
        Returns:
            Path to generated CSV file
        """
        if output_path is None:
            output_path = f"waymap_report_{self.timestamp}.csv"
            
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow([
                    'Scan Type', 'Timestamp', 'URL', 'Parameter', 
                    'Vulnerability Type', 'Severity', 'Payload', 'Details'
                ])
                
                # Data rows
                for scan in self.scan_results.get('scans', []):
                    scan_type = scan.get('scan_type', 'Unknown')
                    timestamp = scan.get('timestamp', '')
                    
                    for vuln in scan.get('vulnerabilities', []):
                        writer.writerow([
                            scan_type,
                            timestamp,
                            vuln.get('url', ''),
                            vuln.get('parameter', ''),
                            vuln.get('type', scan_type),
                            vuln.get('severity', 'Medium'),
                            vuln.get('payload', ''),
                            vuln.get('details', '')
                        ])
                        
            logger.info(f"CSV report generated: {output_path}")
            print_status(f"CSV report saved: {output_path}", "success")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            print_status(f"Error generating CSV report: {e}", "error")
            raise
            
    def generate_markdown_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate Markdown report for documentation
        
        Args:
            output_path: Optional custom output path
            
        Returns:
            Path to generated Markdown file
        """
        if output_path is None:
            output_path = f"waymap_report_{self.timestamp}.md"
            
        try:
            md_content = self._build_markdown_report()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
                
            logger.info(f"Markdown report generated: {output_path}")
            print_status(f"Markdown report saved: {output_path}", "success")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating Markdown report: {e}")
            print_status(f"Error generating Markdown report: {e}", "error")
            raise
            
    def generate_executive_summary(self) -> Dict[str, Any]:
        """
        Generate executive summary of scan results
        
        Returns:
            Dictionary containing summary statistics
        """
        total_scans = len(self.scan_results.get('scans', []))
        total_vulns = sum(
            len(scan.get('vulnerabilities', []))
            for scan in self.scan_results.get('scans', [])
        )
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        scan_types = {}
        
        for scan in self.scan_results.get('scans', []):
            scan_type = scan.get('scan_type', 'Unknown')
            scan_types[scan_type] = scan_types.get(scan_type, 0) + len(scan.get('vulnerabilities', []))
            
            for vuln in scan.get('vulnerabilities', []):
                severity = vuln.get('severity', 'Medium')
                if severity in severity_counts:
                    severity_counts[severity] += 1
                    
        summary = {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'scan_type_breakdown': scan_types,
            'timestamp': datetime.now().isoformat()
        }
        
        return summary
        
    def generate_pdf_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate PDF report
        
        Args:
            output_path: Optional custom output path
            
        Returns:
            Path to generated PDF file
        """
        if output_path is None:
            output_path = f"waymap_report_{self.timestamp}.pdf"
            
        try:
            from fpdf import FPDF
            
            class PDF(FPDF):
                def header(self):
                    self.set_font('Arial', 'B', 15)
                    self.cell(0, 10, 'Waymap Security Scan Report', 0, 1, 'C')
                    self.ln(5)
                    
                def footer(self):
                    self.set_y(-15)
                    self.set_font('Arial', 'I', 8)
                    self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')
            
            pdf = PDF()
            pdf.alias_nb_pages()
            pdf.add_page()
            
            # Executive Summary
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Executive Summary', 0, 1)
            pdf.set_font('Arial', '', 10)
            
            summary = self.generate_executive_summary()
            pdf.cell(0, 8, f"Total Scans: {summary['total_scans']}", 0, 1)
            pdf.cell(0, 8, f"Total Vulnerabilities: {summary['total_vulnerabilities']}", 0, 1)
            pdf.ln(5)
            
            # Severity Breakdown
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Severity Breakdown', 0, 1)
            pdf.set_font('Arial', '', 10)
            
            for severity, count in summary['severity_breakdown'].items():
                pdf.cell(0, 8, f"{severity}: {count}", 0, 1)
            pdf.ln(10)
            
            # Detailed Findings
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Detailed Findings', 0, 1)
            
            for scan in self.scan_results.get('scans', []):
                scan_type = scan.get('scan_type', 'Unknown')
                vulns = scan.get('vulnerabilities', [])
                
                if vulns:
                    pdf.set_font('Arial', 'B', 11)
                    pdf.cell(0, 10, f"{scan_type.upper()} Scan", 0, 1)
                    pdf.set_font('Arial', '', 10)
                    
                    for vuln in vulns:
                        pdf.set_text_color(200, 0, 0) # Red for title
                        pdf.cell(0, 8, f"Type: {vuln.get('type', 'Unknown')}", 0, 1)
                        pdf.set_text_color(0, 0, 0) # Black for text
                        
                        url = vuln.get('url', 'N/A')
                        # Handle long URLs
                        if len(url) > 80:
                            url = url[:77] + "..."
                        pdf.cell(0, 6, f"URL: {url}", 0, 1)
                        
                        pdf.cell(0, 6, f"Severity: {vuln.get('severity', 'Medium')}", 0, 1)
                        pdf.cell(0, 6, f"Parameter: {vuln.get('parameter', 'N/A')}", 0, 1)
                        pdf.ln(5)
            
            pdf.output(output_path)
            
            logger.info(f"PDF report generated: {output_path}")
            print_status(f"PDF report saved: {output_path}", "success")
            return output_path
            
        except ImportError:
            logger.error("fpdf module not found. Cannot generate PDF.")
            print_status("Install fpdf to generate PDF reports: pip install fpdf", "warning")
            return ""
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            print_status(f"Error generating PDF report: {e}", "error")
            raise

    def _build_html_report(self) -> str:
        """Build HTML report content"""
        summary = self.generate_executive_summary()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waymap Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .subtitle {{ opacity: 0.9; font-size: 1.1rem; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        .summary-card h3 {{
            color: #667eea;
            margin-bottom: 10px;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .summary-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #333;
        }}
        .severity-critical {{ border-left-color: #dc3545; }}
        .severity-high {{ border-left-color: #fd7e14; }}
        .severity-medium {{ border-left-color: #ffc107; }}
        .severity-low {{ border-left-color: #28a745; }}
        .scan-results {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .scan-results h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #f0f0f0;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #667eea;
        }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }}
        .code {{ 
            background: #f8f9fa; 
            padding: 2px 6px; 
            border-radius: 3px; 
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Waymap Security Scan Report</h1>
            <p class="subtitle">Generated on {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}</p>
        </header>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Scans</h3>
                <div class="value">{summary['total_scans']}</div>
            </div>
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{summary['total_vulnerabilities']}</div>
            </div>
            <div class="summary-card severity-critical">
                <h3>Critical</h3>
                <div class="value">{summary['severity_breakdown']['Critical']}</div>
            </div>
            <div class="summary-card severity-high">
                <h3>High</h3>
                <div class="value">{summary['severity_breakdown']['High']}</div>
            </div>
            <div class="summary-card severity-medium">
                <h3>Medium</h3>
                <div class="value">{summary['severity_breakdown']['Medium']}</div>
            </div>
            <div class="summary-card severity-low">
                <h3>Low</h3>
                <div class="value">{summary['severity_breakdown']['Low']}</div>
            </div>
        </div>
        
        <div class="scan-results">
            <h2>📊 Detailed Findings</h2>
"""
        
        for scan in self.scan_results.get('scans', []):
            scan_type = scan.get('scan_type', 'Unknown')
            vulns = scan.get('vulnerabilities', [])
            
            if vulns:
                html += f"""
            <h3 style="margin-top: 30px; color: #333;">{scan_type.upper()} Scan</h3>
            <p style="color: #666; margin-bottom: 15px;">Found {len(vulns)} vulnerabilities</p>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Severity</th>
                        <th>Payload</th>
                    </tr>
                </thead>
                <tbody>
"""
                for vuln in vulns:
                    severity = vuln.get('severity', 'Medium')
                    html += f"""
                    <tr>
                        <td><span class="code">{vuln.get('url', 'N/A')}</span></td>
                        <td>{vuln.get('parameter', 'N/A')}</td>
                        <td><span class="badge badge-{severity.lower()}">{severity}</span></td>
                        <td><span class="code">{vuln.get('payload', 'N/A')[:50]}...</span></td>
                    </tr>
"""
                html += """
                </tbody>
            </table>
"""
        
        html += """
        </div>
        
        <footer>
            <p><strong>Waymap v7.1.0</strong> - Advanced Web Vulnerability Scanner</p>
            <p>© 2024-2025 Trixsec Org | Generated with ❤️ by Waymap</p>
        </footer>
    </div>
</body>
</html>
"""
        return html
        
    def _build_markdown_report(self) -> str:
        """Build Markdown report content"""
        summary = self.generate_executive_summary()
        
        md = f"""# Waymap Security Scan Report

**Generated**: {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}  
**Scanner**: Waymap v7.1.0

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Scans | {summary['total_scans']} |
| Total Vulnerabilities | {summary['total_vulnerabilities']} |
| Critical Severity | {summary['severity_breakdown']['Critical']} |
| High Severity | {summary['severity_breakdown']['High']} |
| Medium Severity | {summary['severity_breakdown']['Medium']} |
| Low Severity | {summary['severity_breakdown']['Low']} |

---

## Scan Type Breakdown

"""
        for scan_type, count in summary['scan_type_breakdown'].items():
            md += f"- **{scan_type.upper()}**: {count} vulnerabilities\n"
            
        md += "\n---\n\n## Detailed Findings\n\n"
        
        for scan in self.scan_results.get('scans', []):
            scan_type = scan.get('scan_type', 'Unknown')
            vulns = scan.get('vulnerabilities', [])
            
            if vulns:
                md += f"### {scan_type.upper()} Scan\n\n"
                md += f"Found **{len(vulns)}** vulnerabilities:\n\n"
                
                for i, vuln in enumerate(vulns, 1):
                    md += f"#### {i}. {vuln.get('type', scan_type)}\n\n"
                    md += f"- **URL**: `{vuln.get('url', 'N/A')}`\n"
                    md += f"- **Parameter**: `{vuln.get('parameter', 'N/A')}`\n"
                    md += f"- **Severity**: {vuln.get('severity', 'Medium')}\n"
                    md += f"- **Payload**: `{vuln.get('payload', 'N/A')}`\n"
                    md += f"- **Details**: {vuln.get('details', 'No additional details')}\n\n"
                    
        md += """---

## Recommendations

1. **Immediate Action**: Address all Critical and High severity vulnerabilities
2. **Review**: Analyze Medium severity findings
3. **Monitor**: Track Low severity issues for future remediation
4. **Retest**: Verify fixes after remediation

---

**Report Generated by Waymap v7.1.0**  
© 2024-2025 Trixsec Org
"""
        return md


def generate_all_reports(scan_results: Dict[str, Any], output_dir: str = ".") -> Dict[str, str]:
    """
    Generate all report formats
    
    Args:
        scan_results: Scan results dictionary
        output_dir: Output directory for reports
        
    Returns:
        Dictionary mapping format to file path
    """
    generator = ReportGenerator(scan_results)
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)
    
    reports = {}
    
    try:
        # HTML Report
        html_path = str(output_dir / f"waymap_report_{generator.timestamp}.html")
        reports['html'] = generator.generate_html_report(html_path)
        
        # CSV Report
        csv_path = str(output_dir / f"waymap_report_{generator.timestamp}.csv")
        reports['csv'] = generator.generate_csv_report(csv_path)
        
        # Markdown Report
        md_path = str(output_dir / f"waymap_report_{generator.timestamp}.md")
        reports['markdown'] = generator.generate_markdown_report(md_path)
        
        # PDF Report
        pdf_path = str(output_dir / f"waymap_report_{generator.timestamp}.pdf")
        reports['pdf'] = generator.generate_pdf_report(pdf_path)
        
        print_status(f"All reports generated in: {output_dir}", "success")
        
    except Exception as e:
        logger.error(f"Error generating reports: {e}")
        print_status(f"Error generating some reports: {e}", "warning")
        
    return reports
