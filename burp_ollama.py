"""
BurpOllama - Standalone CLI Tool
Test the analyzer without Burp Suite, or use as a standalone scanner
"""
import argparse
import json
import os
import sys
import requests
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent / "analyzer"))

ANALYZER_URL = "http://127.0.0.1:9999"

def check_server():
    """Check if the analyzer server is running"""
    try:
        r = requests.get(f"{ANALYZER_URL}/api/stats", timeout=3)
        if r.status_code == 200:
            stats = r.json()
            print(f"[+] Server online - {stats.get('total_findings', 0)} findings, {stats.get('total_traffic', 0)} requests")
            return True
    except:
        pass
    print("[-] Analyzer server not running. Start it first: python3 analyzer/server.py")
    return False

def send_file(path):
    """Send a file for analysis"""
    if not os.path.exists(path):
        print(f"[-] File not found: {path}")
        return
    
    with open(path, 'r', errors='ignore') as f:
        content = f.read()
    
    data = {
        "type": "file_upload",
        "url": f"file://{os.path.abspath(path)}",
        "method": "READ",
        "body": content,
        "host": "local",
        "path": path,
        "source": "cli_upload",
        "content_type": "text/plain"
    }
    
    r = requests.post(f"{ANALYZER_URL}/api/analyze", json=data, timeout=60)
    if r.status_code == 200:
        result = r.json()
        pattern_count = len(result.get("pattern_findings", []))
        ai_count = len(result.get("ai_analysis", {}).get("findings", []))
        print(f"[+] Analyzed {path}: {pattern_count} pattern findings, {ai_count} AI findings")
        return result
    else:
        print(f"[-] Error: {r.status_code} - {r.text}")
        return None

def send_url(url):
    """Send a URL for analysis (without actually fetching it - just the pattern)"""
    data = {
        "type": "url_reference",
        "url": url,
        "method": "GET",
        "body": "",
        "host": url.split('/')[2] if '://' in url else url.split('/')[0],
        "path": '/' + '/'.join(url.split('/')[3:]) if '://' in url else '/' + '/'.join(url.split('/')[1:]),
        "source": "cli_upload",
        "content_type": "application/json"
    }
    
    r = requests.post(f"{ANALYZER_URL}/api/analyze", json=data, timeout=60)
    if r.status_code == 200:
        result = r.json()
        pattern_count = len(result.get("pattern_findings", []))
        print(f"[+] Analyzed URL: {pattern_count} pattern findings")
        for f in result.get("pattern_findings", []):
            print(f"  [{f['severity']}] {f['name']} ({f['category']})")
        return result
    else:
        print(f"[-] Error: {r.status_code}")
        return None

def send_raw(method, url, headers_str, body):
    """Send a raw HTTP request for analysis"""
    headers = {}
    if headers_str:
        for line in headers_str.strip().split('\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                headers[key.strip()] = val.strip()
    
    data = {
        "type": "request",
        "url": url,
        "method": method,
        "body": body or "",
        "headers": headers,
        "host": url.split('/')[2] if '://' in url else url,
        "path": '/' + '/'.join(url.split('/')[3:]) if '://' in url else '/',
        "source": "cli_raw",
        "content_type": headers.get("Content-Type", "")
    }
    
    r = requests.post(f"{ANALYZER_URL}/api/analyze", json=data, timeout=60)
    if r.status_code == 200:
        result = r.json()
        pattern_findings = result.get("pattern_findings", [])
        ai_findings = result.get("ai_analysis", {}).get("findings", [])
        
        print(f"\n[+] Analysis Results:")
        print(f"   Pattern Detections: {len(pattern_findings)}")
        print(f"   AI Findings: {len(ai_findings)}")
        
        if pattern_findings:
            print(f"\n{'='*60}")
            print("PATTERN-BASED FINDINGS:")
            print(f"{'='*60}")
            for f in pattern_findings:
                print(f"  [{f['severity']:^8}] {f['name']}")
                print(f"           Category: {f['category']}")
                print(f"           Evidence: {f.get('match', 'N/A')[:100]}")
                print()
        
        if ai_findings:
            print(f"\n{'='*60}")
            print("AI-POWERED FINDINGS (Ollama):")
            print(f"{'='*60}")
            for f in ai_findings:
                print(f"  [{f.get('severity', 'INFO'):^8}] {f.get('vulnerability', 'N/A')}")
                print(f"           Description: {f.get('description', 'N/A')}")
                print(f"           Impact: {f.get('impact', 'N/A')}")
                print(f"           Remediation: {f.get('remediation', 'N/A')}")
                print()
        
        return result
    else:
        print(f"[-] Error: {r.status_code}")
        return None

def list_findings(severity=None):
    """List findings from the server"""
    params = {}
    if severity:
        params["severity"] = severity
    r = requests.get(f"{ANALYZER_URL}/api/findings", params=params, timeout=5)
    if r.status_code == 200:
        data = r.json()
        findings = data.get("findings", [])
        print(f"\n[+] Findings ({len(findings)} total):")
        for f in findings:
            sev = f.get("severity", "INFO")
            name = f.get("name", f.get("vulnerability", "Unknown"))
            url = f.get("url", "")
            print(f"  [{sev:^8}] {name}")
            if url:
                print(f"           {url}")
    else:
        print(f"[-] Error: {r.status_code}")

def get_stats():
    """Get server statistics"""
    r = requests.get(f"{ANALYZER_URL}/api/stats", timeout=5)
    if r.status_code == 200:
        stats = r.json()
        print(f"\n{'='*50}")
        print("BURPOLLAMA STATISTICS")
        print(f"{'='*50}")
        print(f"  Total Traffic:     {stats.get('total_traffic', 0)}")
        print(f"  Total Findings:    {stats.get('total_findings', 0)}")
        print(f"  Total Hosts:       {stats.get('total_hosts', 0)}")
        print(f"  Total Sessions:    {stats.get('total_sessions', 0)}")
        print()
        
        sev = stats.get("severity_counts", {})
        print(f"  Critical: {sev.get('critical', 0)}")
        print(f"  High:     {sev.get('high', 0)}")
        print(f"  Medium:   {sev.get('medium', 0)}")
        print(f"  Low:      {sev.get('low', 0)}")
        print(f"  Info:     {sev.get('info', 0)}")
        print()
        
        cats = stats.get("top_categories", [])
        if cats:
            print("  Top Categories:")
            for cat, count in cats[:5]:
                print(f"    {cat}: {count}")
    else:
        print(f"[-] Error: {r.status_code}")

def main():
    parser = argparse.ArgumentParser(
        description="BurpOllama - Local Bug Hunting Pipeline CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 burp_ollama.py check              # Check if server is running
  python3 burp_ollama.py stats              # Show statistics
  python3 burp_ollama.py send-file ./test.txt  # Analyze a file
  python3 burp_ollama.py send-url https://example.com  # Analyze a URL pattern
  python3 burp_ollama.py raw GET https://target.com/api/users -H "Authorization: Bearer test" -b '{"id":1}'
  python3 burp_ollama.py findings           # List all findings
  python3 burp_ollama.py findings --severity high  # Filter by severity
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # check
    subparsers.add_parser("check", help="Check if server is running")
    
    # stats
    subparsers.add_parser("stats", help="Get server statistics")
    
    # send-file
    p_file = subparsers.add_parser("send-file", help="Send a file for analysis")
    p_file.add_argument("path", help="Path to the file")
    
    # send-url
    p_url = subparsers.add_parser("send-url", help="Analyze a URL pattern")
    p_url.add_argument("url", help="URL to analyze")
    
    # raw
    p_raw = subparsers.add_parser("raw", help="Send raw HTTP data for analysis")
    p_raw.add_argument("method", help="HTTP method (GET, POST, PUT, etc.)")
    p_raw.add_argument("url", help="URL")
    p_raw.add_argument("-H", "--header", action="append", help="Headers (format: 'Key: Value')")
    p_raw.add_argument("-b", "--body", help="Request body")
    
    # findings
    p_findings = subparsers.add_parser("findings", help="List findings")
    p_findings.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], help="Filter by severity")
    
    # batch
    p_batch = subparsers.add_parser("batch", help="Analyze multiple files from a directory")
    p_batch.add_argument("directory", help="Directory with files to analyze")
    p_batch.add_argument("--ext", default=".txt,.json,.js,.html,.xml,.env,.yml,.yaml", help="File extensions to include")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == "check":
        check_server()
    elif args.command == "stats":
        check_server() and get_stats()
    elif args.command == "send-file":
        check_server() and send_file(args.path)
    elif args.command == "send-url":
        check_server() and send_url(args.url)
    elif args.command == "raw":
        check_server() and send_raw(args.method, args.url, '\n'.join(args.header or []), args.body)
    elif args.command == "findings":
        check_server() and list_findings(args.severity)
    elif args.command == "batch":
        if not check_server():
            return
        exts = [e.strip() for e in args.ext.split(',')]
        files = []
        for ext in exts:
            files.extend(Path(args.directory).rglob(f"*{ext}"))
        for f in files:
            send_file(str(f))

if __name__ == "__main__":
    main()
