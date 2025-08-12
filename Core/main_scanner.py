import os
import sys
import json
from datetime import datetime

# Import scan functions from other scripts
from Xss import scan_xss
from Sqli import scan_sqli
from final2 import run_scan
from scanner_gui import scan_csrf_and_sensitive_data

def ensure_reports_folder():
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

def run_all_scans(url, password_dir=None):
    reports_dir = ensure_reports_folder()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary = []

    # XSS Scan
    try:
        print("\n[=] Running XSS scan...")
        xss_report_path = os.path.join(reports_dir, f"xss_report_{timestamp}.json")
        scan_xss(url)
        if os.path.exists("xss_results.json"):
            os.replace("xss_results.json", xss_report_path)
            summary.append(("XSS", "Completed", xss_report_path))
        else:
            summary.append(("XSS", "No results file", "-"))
    except Exception as e:
        summary.append(("XSS", f"Error: {e}", "-"))

    # SQLi Scan
    try:
        print("\n[=] Running SQL Injection scan...")
        sqli_report_path = os.path.join(reports_dir, f"sqli_report_{timestamp}.json")
        scan_sqli(url)
        if os.path.exists("sqli_results.json"):
            os.replace("sqli_results.json", sqli_report_path)
            summary.append(("SQLi", "Completed", sqli_report_path))
        else:
            summary.append(("SQLi", "No results file", "-"))
    except Exception as e:
        summary.append(("SQLi", f"Error: {e}", "-"))

    # Auth/Session/IDOR Scan
    try:
        print("\n[=] Running Auth/Session/IDOR scan...")
        final2_report_path = os.path.join(reports_dir, f"final2_report_{timestamp}.txt")
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        if password_dir:
            run_scan(url, password_directory=password_dir)
        else:
            run_scan(url)
        sys.stdout = old_stdout
        with open(final2_report_path, "w", encoding="utf-8") as f:
            f.write(mystdout.getvalue())
        summary.append(("Auth/Session/IDOR", "Completed", final2_report_path))
    except Exception as e:
        summary.append(("Auth/Session/IDOR", f"Error: {e}", "-"))

    # CSRF & Sensitive Data Scan
    try:
        print("\n[=] Running CSRF & Sensitive Data scan...")
        csrf_report_path = os.path.join(reports_dir, f"csrf_sensitive_report_{timestamp}.txt")
        report, _ = scan_csrf_and_sensitive_data(url)
        with open(csrf_report_path, "w", encoding="utf-8") as f:
            f.write(report)
        summary.append(("CSRF/Sensitive Data", "Completed", csrf_report_path))
    except Exception as e:
        summary.append(("CSRF/Sensitive Data", f"Error: {e}", "-"))

    # Summary string for UI
    output_lines = []
    output_lines.append("\n=== Scan Summary ===")
    output_lines.append(f"{'Scan':<25} {'Status':<20} {'Report File'}")
    output_lines.append("-" * 70)
    for scan, status, path in summary:
        output_lines.append(f"{scan:<25} {status:<20} {path}")
    output_lines.append("-" * 70)
    output_lines.append(f"All reports are saved in: {reports_dir}")

    return "\n".join(output_lines)

# ---------------- Gradio UI ----------------
import gradio as gr

def gradio_interface(url, password_dir):
    return run_all_scans(url, password_dir if password_dir else None)

with gr.Blocks() as demo:
    gr.Markdown("##🛡 Web Vulnerability Scanner")
    url_input = gr.Textbox(label="Target URL", placeholder="http://testphp.vulnweb.com/listproducts.php?cat=1")
    pwd_dir_input = gr.Textbox(label="Password Directory (optional)", placeholder="Path to password payloads folder")
    run_button = gr.Button("Run Scan")
    output_box = gr.Textbox(label="Scan Output", lines=20)

    run_button.click(fn=gradio_interface, inputs=[url_input, pwd_dir_input], outputs=output_box)

if __name__ == "__main__":
    demo.launch()
