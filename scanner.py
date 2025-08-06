import requests
import socket
import ssl
import json
import os
import dns.resolver
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

# Attempt to import nmap, but allow the script to run without it.
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: 'python-nmap' library not found or nmap is not installed. Falling back to basic port scan.")

# --- Assumed Database Model (in models.py) ---
# This part is commented out as models.py is imported separately in app.py if needed here.
# from flask_sqlalchemy import SQLAlchemy
# db = SQLAlchemy()
# class Scan(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     url = db.Column(db.String(255), nullable=False)
#     status = db.Column(db.String(100), nullable=False)
#     findings = db.Column(db.Text)
#     recommendations = db.Column(db.Text)
#     timestamp = db.Column(db.DateTime, default=datetime.utcnow)
# from models import Scan, db # This import is likely not needed in scanner_engine.py itself,
                             # as the DB interaction is handled by app.py's background task.

# --- Helper Function ---
def safe_request(url, **kwargs):
    """A wrapper for requests.get that safely handles exceptions."""
    try:
        headers = kwargs.get("headers", {})
        if "User-Agent" not in headers:
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        kwargs["headers"] = headers
        
        return requests.get(url, timeout=10, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {url}: {e}")
        return None

# --- Information Gathering Functions ---

def get_wayback_snapshots(url):
    """Queries the Wayback Machine for the closest archived snapshot of a domain."""
    try:
        domain = urlparse(url).netloc
        api_url = f"https://archive.org/wayback/available?url={domain}"
        res = safe_request(api_url)
        if not res:
            return {"status": "Error: Request to Wayback API failed"}
        
        data = res.json()
        snapshot = data.get("archived_snapshots", {}).get("closest", {})
        
        if snapshot and snapshot.get("available"):
            return {
                "status": "Available", 
                "url": snapshot.get("url"), 
                "timestamp": snapshot.get("timestamp")
            }
        return {"status": "No snapshots found"}
    except Exception as e:
        return {"status": f"Error: {e}"}

def get_ssl_certificate_info(hostname):
    """Retrieves and parses the SSL certificate for a given hostname."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "expires": cert.get('notAfter')
                }
    except Exception as e:
        return {"error": f"Could not retrieve SSL certificate: {e}"}

def get_whois_info(domain):
    """Fetches WHOIS information for a domain."""
    try:
        info = whois.whois(domain)
        # Ensure dates are strings for JSON serialization
        creation_date = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
        expiration_date = info.expiration_date[0] if isinstance(info.expiration_date, list) else info.expiration_date
        return {
            "registrar": info.registrar,
            "creation_date": str(creation_date),
            "expiration_date": str(expiration_date),
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

def get_dns_records(hostname):
    """Fetches common DNS records for a hostname."""
    records = {}
    for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(hostname, record_type)
            records[record_type] = [rdata.to_text().strip('"') for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[record_type] = "Not found"
        except Exception as e:
            records[record_type] = f"Error: {e}"
    return records

def perform_port_scan(hostname):
    """Performs a port scan using Nmap if available, otherwise a basic TCP connect scan."""
    # Nmap Scan (Preferred)
    if NMAP_AVAILABLE:
        try:
            nm = nmap.PortScanner()
            # -F: Fast scan (fewer ports than the default scan)
            nm.scan(hosts=hostname, arguments='-F')
            open_ports = []
            if hostname in nm.all_hosts():
                for proto in nm[hostname].all_protocols():
                    lport = nm[hostname][proto].keys()
                    for port in sorted(lport):
                        state = nm[hostname][proto][port]['state']
                        if state == 'open':
                            open_ports.append(f"{port}/{proto}")
            return {"method": "nmap", "open_ports": open_ports if open_ports else "None found"}
        except Exception as e:
            print(f"Nmap scan failed: {e}. Falling back to basic scan.")
    
    # Basic TCP Connect Scan (Fallback)
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    try:
        ip = socket.gethostbyname(hostname)
        for port in common_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(f"{port}/tcp")
        return {"method": "basic", "open_ports": open_ports if open_ports else "None found"}
    except socket.gaierror:
        return {"error": "Could not resolve host"}
    except Exception:
        return {"error": "Basic port scan failed"}

def check_security_headers(url):
    """Checks for the presence of important security headers."""
    res = safe_request(url)
    if not res:
        return {"error": "Could not fetch URL to check headers."}
        
    headers = res.headers
    expected = {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    }
    found = set(headers.keys())
    missing = list(expected - found)
    return {"missing": missing}

# --- Subdomain Enumeration Functions ---

def fetch_subdomains_crtsh(domain):
    """Query crt.sh for subdomains."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    res = safe_request(url)
    if not res: raise RuntimeError("crt.sh request failed")
    
    subs = set()
    for item in res.json():
        for entry in item.get("name_value", "").splitlines():
            entry = entry.strip().lower().rstrip('.')
            if '*' not in entry and entry.endswith(domain.lower()):
                subs.add(entry)
    return subs

def enumerate_subdomains(url):
    """High-level wrapper to enumerate subdomains from various sources."""
    domain = urlparse(url).hostname or url
    domain = domain.lstrip("www.")

    try:
        subs = fetch_subdomains_crtsh(domain)
        if subs:
            return {"subdomains": sorted(list(subs)), "error": None}
        return {"subdomains": [], "error": "No subdomains found via crt.sh."}
    except Exception as e:
        return {"subdomains": [], "error": f"Subdomain enumeration failed: {e}"}

# --- Vulnerability Testing Functions ---

def test_sql_injection(url, scan_data):
    """Tests for basic SQL injection vulnerabilities."""
    try:
        scan_data['active_tests'].append({
            "test": "SQL Injection",
            "status": "Performed"
        })
        payloads = ["' OR '1'='1", "' OR 1=1--", '" OR "1"="1']
        error_keywords = ["sql syntax", "mysql", "unclosed quotation mark", "odbc"]
        
        for payload in payloads:
            # Avoid modifying URLs without parameters in a meaningless way
            if '?' not in url: continue
            
            test_url = f"{url}&testparam={payload}"
            res = safe_request(test_url)
            if res and any(keyword in res.text.lower() for keyword in error_keywords):
                # If vulnerability is found, add it to 'vulnerabilities' list in scan_data
                if 'vulnerabilities' not in scan_data:
                    scan_data['vulnerabilities'] = []
                scan_data['vulnerabilities'].append({
                    "type": "SQL Injection",
                    "severity": "High",
                    "summary": f"Possible SQL Injection vulnerability with payload: {payload}",
                    "recommendation": "Use parameterized queries or prepared statements to prevent SQL Injection."
                })
                return f"❗ High: SQL Injection likely with payload: {payload}" # Also return for findings list
        return None
    except Exception as e:
        print("SQL Injection test failed:", e)
        scan_data['active_tests'].append({
            "test": "SQL Injection",
            "status": "Error"
        })
        return None

def test_xss(url, scan_data):
    """Tests for basic reflected Cross-Site Scripting (XSS)."""
    try:
        scan_data['active_tests'].append({
            "test": "XSS",
            "status": "Performed"
        })
        payload = "<script>alert('XSS-Test-Here-123')</script>"
        if '?' not in url: return None # Only test pages with params
        
        test_url = f"{url}&q={payload}"
        res = safe_request(test_url)
        if res and payload in res.text:
            # If vulnerability is found, add it to 'vulnerabilities' list in scan_data
            if 'vulnerabilities' not in scan_data:
                scan_data['vulnerabilities'] = []
            scan_data['vulnerabilities'].append({
                "type": "XSS",
                "severity": "Medium",
                "summary": "Reflected XSS vulnerability detected.",
                "recommendation": "Implement strict, context-aware output encoding and a strong Content Security Policy (CSP) to mitigate XSS."
            })
            return "⚠️ Medium: Reflected XSS vulnerability detected." # Also return for findings list
        return None
    except Exception as e:
        print("XSS test failed:", e)
        scan_data['active_tests'].append({
            "test": "XSS",
            "status": "Error"
        })
        return None

def test_open_redirect(url, scan_data):
    """Tests for open redirect vulnerabilities."""
    try:
        scan_data['active_tests'].append({
            "test": "Open Redirect",
            "status": "Performed"
        })
        payload = "https://evil.com"
        if '?' not in url: return None # Only test pages with params

        test_url = f"{url}&redirect={payload}"
        res = safe_request(test_url, allow_redirects=False)
        if res and res.status_code in (301, 302, 307, 308) and 'location' in res.headers and payload in res.headers['location']:
            # If vulnerability is found, add it to 'vulnerabilities' list in scan_data
            if 'vulnerabilities' not in scan_data:
                scan_data['vulnerabilities'] = []
            scan_data['vulnerabilities'].append({
                "type": "Open Redirect",
                "severity": "Medium",
                "summary": "Open Redirect vulnerability detected.",
                "recommendation": "Avoid user-controlled redirects. If necessary, use a whitelist of approved redirect targets."
            })
            return "🔁 Medium: Open Redirect vulnerability detected." # Also return for findings list
        return None
    except Exception as e:
        print("Open Redirect test failed:", e)
        scan_data['active_tests'].append({
            "test": "Open Redirect",
            "status": "Error"
        })
        return None

def test_directory_traversal(url, scan_data):
    """Tests for directory traversal vulnerabilities."""
    try:
        scan_data['active_tests'].append({
            "test": "Directory Traversal",
            "status": "Performed"
        })
        payload = "../../../../../etc/passwd"
        # Normalize URL to avoid double slashes
        base_url = url.rstrip('/')
        test_url = f"{base_url}/{payload}"
        res = safe_request(test_url)
        if res and "root:x:0:0" in res.text:
            # If vulnerability is found, add it to 'vulnerabilities' list in scan_data
            if 'vulnerabilities' not in scan_data:
                scan_data['vulnerabilities'] = []
            scan_data['vulnerabilities'].append({
                "type": "Directory Traversal",
                "severity": "High",
                "summary": "Directory Traversal vulnerability confirmed.",
                "recommendation": "Validate user-supplied file paths and run the application with the minimum necessary file system permissions."
            })
            return "❗ High: Directory Traversal vulnerability confirmed." # Also return for findings list
        return None
    except Exception as e:
        print("Directory Traversal test failed:", e)
        scan_data['active_tests'].append({
            "test": "Directory Traversal",
            "status": "Error"
        })
        return None
    
def test_vulnerable_js(url, scan_data):
    """Extracts JS files and checks them against a local vulnerability database."""
    try:
        scan_data['active_tests'].append({
            "test": "Vulnerable JS Libraries",
            "status": "Performed"
        })
        findings = []
        # Ensure scan_data has a 'js_libraries' key initialized to store results
        if 'js_libraries' not in scan_data:
            scan_data['js_libraries'] = []

        try:
            with open("jsrepository-v2.json", "r") as f:
                repo = json.load(f)
        except FileNotFoundError:
            scan_data['active_tests'].append({
                "test": "Vulnerable JS Libraries",
                "status": "Error"
            })
            return ["Could not find jsrepository-v2.json to check libraries."]
        except json.JSONDecodeError:
            scan_data['active_tests'].append({
                "test": "Vulnerable JS Libraries",
                "status": "Error"
            })
            return ["Error decoding jsrepository-v2.json."]

        res = safe_request(url)
        if not res: 
            scan_data['active_tests'].append({
                "test": "Vulnerable JS Libraries",
                "status": "Error"
            })
            return ["Could not fetch page to check for JS libraries."]

        soup = BeautifulSoup(res.text, "html.parser")
        js_urls = [script['src'] for script in soup.find_all("script", src=True)]

        vulnerable_libs_found_for_report = []
        for js_url in js_urls:
            lib_name = os.path.basename(js_url).split('?')[0].lower()
            found_vulnerability = False
            for repo_name, lib_data in repo.items():
                if repo_name in lib_name:
                    for vuln in lib_data.get("vulnerabilities", []):
                        summary = vuln.get("identifiers", {}).get("summary", "No summary available")
                        severity = vuln.get("severity", "Low") # Default severity
                        recommendation = vuln.get("recommendation", "Update vulnerable JavaScript libraries to their latest, patched versions.")

                        findings.append(f"💻 {severity}: Vulnerable JS library found: {repo_name} - {summary}")
                        
                        # Add to scan_data['vulnerabilities'] for overall count and PDF/CSV
                        if 'vulnerabilities' not in scan_data:
                            scan_data['vulnerabilities'] = []
                        scan_data['vulnerabilities'].append({
                            "type": "Vulnerable JS Library",
                            "severity": severity,
                            "summary": f"{repo_name}: {summary}",
                            "recommendation": recommendation
                        })
                        
                        # Add to scan_data['js_libraries'] for the specific JS report section
                        scan_data['js_libraries'].append({
                            "library": repo_name,
                            "version": "Unknown", # You might need a more sophisticated way to get actual version
                            "severity": severity,
                            "summary": summary
                        })
                        found_vulnerability = True
            if not found_vulnerability:
                # If no specific vulnerability found but library is identified,
                # you might want to log it as 'No Issues' or just skip.
                # For now, we'll ensure the list is not empty if no vulns are found.
                pass 
        
        if not scan_data['js_libraries']: # If no JS libraries were identified as vulnerable or present
            scan_data['js_libraries'].append({
                "library": "N/A",
                "version": "-",
                "severity": "-",
                "summary": "No vulnerable libraries found"
            })

        return findings if findings else None
    except Exception as e:
        print("Vulnerable JS Libraries test failed:", e)
        scan_data['active_tests'].append({
            "test": "Vulnerable JS Libraries",
            "status": "Error"
        })
        return ["An error occurred during vulnerable JS library check."]


# --- Main Scan Orchestrator ---

def run_information_scan(url): # <-- Renamed run_scan to run_information_scan
    """Runs a full suite of scans and returns a dictionary with findings and recommendations."""
    scan_data = {
        "url": url,
        "findings": [],
        "recommendations": [],
        "status": "Completed",
        "timestamp": datetime.now(),
        "active_tests": [],  # Initialize active_tests list here
        "vulnerabilities": [], # Initialize general vulnerabilities list
        "js_libraries": [] # Initialize js_libraries list for reporting
    }

    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ('http', 'https'):
            raise ValueError("URL must start with http:// or https://")
        hostname = parsed_url.netloc

        # --- Run all checks and collect findings & recommendations ---

        # 1. Subdomain Enumeration
        scan_data['active_tests'].append({"test": "Subdomain Enumeration", "status": "Performed"})
        try:
            subdomain_result = enumerate_subdomains(url)
            if subdomain_result["subdomains"]:
                subs = subdomain_result["subdomains"]
                preview = ", ".join(subs[:3]) + ("..." if len(subs) > 3 else "")
                scan_data["findings"].append(f"🌐 Info: Found {len(subs)} subdomains (e.g., {preview}).")
                scan_data["recommendations"].append("Review all discovered subdomains for potential security risks and unauthorized deployments.")
            elif subdomain_result["error"]:
                scan_data["findings"].append(f"⚠️ Warning: Subdomain scan failed: {subdomain_result['error']}")
                scan_data['active_tests'][-1]['status'] = "Error" # Update status to Error
            scan_data['subdomains'] = subdomain_result # Store full subdomain result
        except Exception as e:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: Subdomain enumeration error: {e}")


        # 2. SSL Certificate
        scan_data['active_tests'].append({"test": "SSL Certificate", "status": "Performed"})
        try:
            ssl_info = get_ssl_certificate_info(hostname)
            if "error" in ssl_info:
                scan_data["findings"].append(f"⚠️ Warning: {ssl_info['error']}")
                scan_data["recommendations"].append("Ensure a valid, trusted SSL/TLS certificate is installed and properly configured for this domain.")
                scan_data['active_tests'][-1]['status'] = "Error"
            else:
                scan_data["findings"].append(f"🔒 Info: SSL cert expires on {ssl_info.get('expires')}, issued by {ssl_info.get('issuer', {}).get('commonName')}")
            scan_data['ssl'] = ssl_info # Store full SSL result
        except Exception as e:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: SSL Certificate check error: {e}")

        # 3. WHOIS
        scan_data['active_tests'].append({"test": "WHOIS Information", "status": "Performed"})
        try:
            whois_info = get_whois_info(hostname)
            if "error" not in whois_info:
                scan_data["findings"].append(f"👤 Info: Domain registered by {whois_info['registrar']}, expires on {whois_info['expiration_date']}.")
            else:
                scan_data['active_tests'][-1]['status'] = "Error"
                scan_data["findings"].append(f"⚠️ Warning: WHOIS lookup failed: {whois_info['error']}")
            scan_data['whois'] = whois_info # Store full WHOIS result
        except Exception as e:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: WHOIS lookup error: {e}")
            
        # 4. Security Headers
        scan_data['active_tests'].append({"test": "Security Headers", "status": "Performed"})
        try:
            header_info = check_security_headers(url)
            if "error" not in header_info and header_info["missing"]:
                missing_str = ", ".join(header_info['missing'])
                scan_data["findings"].append(f"🛡️ Low: Missing security headers: {missing_str}")
                for h in header_info["missing"]:
                    scan_data["recommendations"].append(f"Implement the {h} HTTP security header to enhance protection.")
            elif "error" in header_info:
                scan_data['active_tests'][-1]['status'] = "Error"
                scan_data["findings"].append(f"⚠️ Warning: Security Headers check failed: {header_info['error']}")
            scan_data['http_headers'] = header_info # Store full header result (missing headers)
            # You might want to store *all* headers for the report, not just missing ones.
            # E.g., fetch and store res.headers directly, then process for 'missing'.
        except Exception as e:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: Security Headers check error: {e}")


        # 5. DNS Records
        scan_data['active_tests'].append({"test": "DNS Records", "status": "Performed"})
        try:
            dns_info = get_dns_records(hostname)
            scan_data["findings"].append(f"🌐 Info: DNS A Record for {hostname}: {dns_info.get('A', 'N/A')}")
            scan_data['dns'] = dns_info # Store full DNS result
        except Exception as e:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: DNS Records check error: {e}")

        # 6. Port Scan
        scan_data['active_tests'].append({"test": "Port Scan", "status": "Performed"})
        try:
            port_scan_results = perform_port_scan(hostname)
            if "error" not in port_scan_results:
                ports = port_scan_results.get('open_ports', 'N/A')
                method = port_scan_results.get('method', 'scan')
                scan_data["findings"].append(f"🔌 Info: Open ports found via {method} scan: {ports}")
                if ports != "None found":
                    scan_data["recommendations"].append("Review all open ports. Ensure that only necessary ports are exposed to the internet and are properly firewalled.")
            else:
                scan_data['active_tests'][-1]['status'] = "Error"
                scan_data["findings"].append(f"⚠️ Warning: Port Scan failed: {port_scan_results['error']}")
            scan_data['port_scan'] = port_scan_results # Store full port scan result
        except Exception as e:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: Port Scan error: {e}")

        # 7. Vulnerability Tests - Pass scan_data to each test
        # These functions (test_sql_injection, test_xss, etc.) are already designed
        # to add to scan_data['active_tests'] and scan_data['vulnerabilities'].
        tests = [
            test_sql_injection,
            test_xss,
            test_open_redirect,
            test_directory_traversal,
            test_vulnerable_js # This one also populates scan_data['js_libraries']
        ]
        
        # Recommendations are now added directly by the test functions when a vuln is found.
        # We'll just collect findings here.
        for test_func in tests:
            # Each test_func will add its status to active_tests and its findings to scan_data['vulnerabilities']
            # and potentially update scan_data['js_libraries'].
            # The return value from test_func (e.g., "❗ High: SQL Injection...")
            # is primarily for the general 'findings' list.
            result_message = test_func(url, scan_data) 
            if result_message:
                if isinstance(result_message, list):
                    scan_data["findings"].extend(result_message)
                else:
                    scan_data["findings"].append(result_message)

    except Exception as e:
        scan_data["status"] = f"Error: {str(e)}"
        scan_data["findings"].append(f"Critical error during scan: {e}")
        # Mark all pending active tests as error if a critical error occurs
        for test in scan_data['active_tests']:
            if test['status'] == 'Performed': # Or 'Pending', if you have such a status
                test['status'] = 'Error'


    if not scan_data["findings"]:
        scan_data["findings"].append("✅ No immediate low-hanging vulnerabilities or informational items were found.")

    # Consolidate recommendations from `scan_data['vulnerabilities']` and other direct additions
    final_recommendations = set(scan_data.get('recommendations', []))
    for vuln in scan_data.get('vulnerabilities', []):
        if vuln.get('recommendation'):
            final_recommendations.add(vuln['recommendation'])
    scan_data["recommendations"] = sorted(list(final_recommendations))

    # The database saving part (Scan(...), db.session.add(scan), db.session.commit())
    # was in the original scanner.py, but in the app.py you provided,
    # this logic is handled in `run_scan_in_background`.
    # So, `run_information_scan` should just *return* `scan_data`.

    return scan_data