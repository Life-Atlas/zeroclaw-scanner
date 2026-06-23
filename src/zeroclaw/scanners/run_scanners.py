import sys
from pathlib import Path
from pattern_scanner import scan_patterns
from auth_scanner import scan_fastapi_auth, scan_supabase_rls
from secret_scanner import scan_secrets
from dependency_scanner import scan_dependencies

def main():
    target_dir_path = r"C:\Users\mrvar\lpi-platform"
    target_dir = Path(target_dir_path)
    
    report_md = "# Security Scan Report\n\n"
    report_md += f"**Target Directory:** `{target_dir_path}`\n\n"
    
    print(f"Scanning target directory: {target_dir_path}")
    print("-" * 50)
    
    print("Running pattern_scanner...")
    report_md += "## Pattern Scanner\n\n"
    try:
        findings = scan_patterns(target_dir)
        print(f"Found {len(findings)} findings.")
        if findings:
            for f in findings:
                print(f"  [{f.severity.name}] {f.title}: {f.file_path}:{f.line_number}")
                report_md += f"- **[{f.severity.name}]** {f.title}: `{f.file_path}:{f.line_number}`\n"
        else:
            report_md += "No findings.\n"
        report_md += "\n"
    except Exception as e:
        print(f"Error running pattern_scanner: {e}")
        report_md += f"**Error:** `{e}`\n\n"
        
    print("-" * 50)
    
    print("Running auth_scanner...")
    report_md += "## Auth Scanner (FastAPI)\n\n"
    try:
        findings = scan_fastapi_auth(target_dir)
        print(f"Found {len(findings)} findings in FastAPI auth.")
        if findings:
            for f in findings:
                print(f"  [{f.severity.name}] {f.title}: {f.file_path}:{f.line_number}")
                report_md += f"- **[{f.severity.name}]** {f.title}: `{f.file_path}:{f.line_number}`\n"
        else:
            report_md += "No findings.\n"
        report_md += "\n"
    except Exception as e:
        print(f"Error running auth_scanner: {e}")
        report_md += f"**Error:** `{e}`\n\n"
        
    report_md += "## Auth Scanner (Supabase RLS)\n\n"
    try:
        findings = scan_supabase_rls(target_dir)
        print(f"Found {len(findings)} findings in Supabase RLS.")
        if findings:
            for f in findings:
                print(f"  [{f.severity.name}] {f.title}: {f.file_path}:{f.line_number}")
                report_md += f"- **[{f.severity.name}]** {f.title}: `{f.file_path}:{f.line_number}`\n"
        else:
            report_md += "No findings.\n"
        report_md += "\n"
    except NotImplementedError as e:
        print(f"scan_supabase_rls not implemented: {e}")
        report_md += f"**Not Implemented:** `{e}`\n\n"
    except Exception as e:
        print(f"Error running scan_supabase_rls: {e}")
        report_md += f"**Error:** `{e}`\n\n"
        
    print("-" * 50)
    
    print("Running secret_scanner...")
    report_md += "## Secret Scanner\n\n"
    try:
        findings = scan_secrets(target_dir)
        print(f"Found {len(findings)} findings.")
        if findings:
            for f in findings:
                print(f"  [{f.severity.name}] {f.title}: {f.file_path}:{f.line_number}")
                report_md += f"- **[{f.severity.name}]** {f.title}: `{f.file_path}:{f.line_number}`\n"
        else:
            report_md += "No findings.\n"
        report_md += "\n"
    except Exception as e:
        print(f"Error running secret_scanner: {e}")
        report_md += f"**Error:** `{e}`\n\n"
        
    print("-" * 50)
    
    print("Running dependency_scanner...")
    report_md += "## Dependency Scanner\n\n"
    try:
        findings = scan_dependencies(target_dir)
        print(f"Found {len(findings)} findings.")
        if findings:
            for f in findings:
                print(f"  [{f.severity.name}] {f.title}: {f.file_path}:{f.line_number}")
                report_md += f"- **[{f.severity.name}]** {f.title}: `{f.file_path}:{f.line_number}`\n"
        else:
            report_md += "No findings.\n"
        report_md += "\n"
    except Exception as e:
        print(f"Error running dependency_scanner: {e}")
        report_md += f"**Error:** `{e}`\n\n"
        
    print("-" * 50)
    
    report_file = Path("scan_report.md")
    report_file.write_text(report_md, encoding="utf-8")
    print(f"Scanning complete. Report saved to {report_file.absolute()}")

if __name__ == '__main__':
    main()
