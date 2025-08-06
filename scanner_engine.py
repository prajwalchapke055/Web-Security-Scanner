import whois
import dns.resolver
import ssl
import socket
import subprocess
from datetime import datetime
from urllib.parse import urlparse
import requests
import builtwith
import json
import re
import os # Import os for path joining

# --- Nmap availability check at the top ---
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    # print("Warning: 'python-nmap' library not found. Falling back to basic port scan if Nmap is not installed/found.")

# --- VULNERABILITY CONTEXT HELPERS (REMOVED) ---
# VULN_CONTEXT_DATA = None 
# Removed _load_vulnerability_context and add_vulnerability_context functions.


# --- Helper function ---
def get_domain_from_url(url):
    try:
        if '://' not in url:
            url = 'http://' + url
        return urlparse(url).netloc
    except Exception:
        return None

# --- JavaScript Library Vulnerability Scanner ---
def analyze_js_libraries(tech_stack):
    vulnerable_libs = []
    try:
        file_path = os.path.join(os.path.dirname(__file__), 'jsrepository.json') 
        with open(file_path, 'r', encoding='utf-8') as f:
            repo = json.load(f)
        
        if not tech_stack:
            return {"vulnerable_libraries": [], "all_identified_js_libs": [], "error": "No tech stack found to analyze JS libraries."}

        js_frameworks = tech_stack.get('javascript-frameworks', [])
        
        all_identified_js_libs = []

        for lib_string in js_frameworks:
            match = re.match(r'([^:]+):([\d\.]+)', lib_string) 
            if not match: 
                all_identified_js_libs.append({"library": lib_string, "version": "N/A", "severity": "Info", "summary": "No version detected or vulnerability data."})
                continue
            
            lib_name, version_str = match.groups()
            lib_name_lower = lib_name.lower()
            
            is_vulnerable_instance = False
            if lib_name_lower in repo:
                vulnerabilities = repo[lib_name_lower].get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    affected_versions_below = vuln.get('below')
                    if affected_versions_below:
                        try:
                            if tuple(map(int, version_str.split('.'))) < tuple(map(int, affected_versions_below.split('.'))):
                                vulnerable_libs.append({
                                    "library": lib_name, 
                                    "version": version_str,
                                    "severity": vuln.get('severity', 'Medium'), 
                                    "summary": vuln.get('info', 'No summary available.')
                                })
                                # Removed add_vulnerability_context call here
                                is_vulnerable_instance = True
                                break 
                        except ValueError:
                            continue
            
            if not is_vulnerable_instance:
                all_identified_js_libs.append({"library": lib_name, "version": version_str, "severity": "None", "summary": "No known vulnerabilities for this version."})

        return {"vulnerable_libraries": vulnerable_libs, "all_identified_js_libs": all_identified_js_libs}

    except FileNotFoundError:
        return {"error": "Vulnerability database (jsrepository.json) not found.", "vulnerable_libraries": [], "all_identified_js_libs": []}
    except Exception as e:
        return {"error": f"An error occurred during JS library analysis: {e}", "vulnerable_libs": [], "all_identified_js_libs": []}

# --- Subdomain Enumeration Function ---
def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status() 

        data = response.json()
        subdomains = set()
        for item in data:
            name = item.get("name_value")
            if name:
                for sub in name.split('\n'):
                    if sub.strip().endswith(domain) and '*' not in sub:
                        subdomains.add(sub.strip().lower()) 
        return {"subdomains": sorted(list(subdomains))}
    except requests.exceptions.Timeout as e: 
        return {"error": f"Connection to crt.sh timed out after 10 seconds. This might be a network issue or crt.sh is temporarily unavailable. ({str(e)})"}
    except requests.exceptions.ConnectionError as e: 
        return {"error": f"Could not connect to crt.sh. Please check your internet connection, DNS, or proxy settings. ({str(e)})"}
    except requests.exceptions.RequestException as e: 
        return {"error": f"An HTTP error occurred while fetching subdomains from crt.sh: {str(e)}"}
    except Exception as e: 
        return {"error": f"An unexpected error occurred during subdomain enumeration: {str(e)}"}

# --- Port Scanning Function ---
def _basic_port_scan_socket(host, ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080, 8443]):
    """A helper for the basic TCP connect scan."""
    open_ports = []
    # Get IP address once to avoid repeated DNS lookups
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": "Could not resolve host for basic port scan.", "method": "basic", "message": "Fallback used due to Nmap unavailability — Basic TCP scan"}

    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=1.5): # Use a consistent timeout
                open_ports.append(f"{port}/tcp")
        except (socket.timeout, ConnectionRefusedError, OSError): # Specific exceptions for closed/filtered ports
            continue
        except Exception: # Catch any other unexpected socket errors
            continue # Just continue to next port, don't break the whole scan

    return {"method": "basic", "open_ports": open_ports if open_ports else "None found", "message": "Fallback used due to Nmap unavailability — Basic TCP scan"}


def perform_port_scan(hostname):
    """
    Performs a port scan using Nmap via subprocess if available,
    otherwise falls back to a basic Python socket connect scan.
    """
    nmap_executable_found = False
    try:
        # Try to find nmap executable in PATH
        subprocess.run(['nmap', '--version'], capture_output=True, check=True, text=True, timeout=5)
        nmap_executable_found = True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # Nmap command failed, not found, or timed out.
        nmap_executable_found = False
    except Exception as e:
        # General error checking nmap availability
        nmap_executable_found = False


    if nmap_executable_found:
        try:
            # Use subprocess to run nmap command directly
            # -F: Fast scan (fewer ports than the default scan)
            # -oG - : Output in greppable format to stdout
            # -Pn: Treat all hosts as online -- skip host discovery (useful if ping is blocked)
            cmd = ['nmap', '-F', '-Pn', hostname]
            result = subprocess.run(cmd, capture_output=True, check=True, text=True, timeout=60) # Increased timeout
            
            open_ports = []
            # Parse the Nmap greppable output
            # Example line: Host: 192.168.1.1 () Ports: 22/open/tcp//ssh//, 80/open/tcp//http//
            for line in result.stdout.splitlines():
                if "Ports:" in line:
                    ports_str = line.split("Ports:")[1].strip()
                    for port_info in ports_str.split(','):
                        parts = port_info.strip().split('/')
                        if len(parts) >= 3 and parts[1] == 'open':
                            port = parts[0]
                            proto = parts[2]
                            service = parts[4] if len(parts) > 4 else 'unknown'
                            open_ports.append(f"{port}/{proto} ({service})")
            
            return {"method": "nmap", "open_ports": open_ports if open_ports else "None found"}
        except subprocess.CalledProcessError as e:
            # Nmap ran but returned non-zero (e.g., host down, scan failed for specific reason)
            # print(f"Nmap subprocess scan failed: {e.stderr}. Falling back to basic scan.")
            pass # Fall through to basic scan
        except subprocess.TimeoutExpired:
            # print("Nmap subprocess timed out. Falling back to basic scan.")
            pass # Fall through to basic scan
        except Exception as e:
            # General error during Nmap execution via subprocess
            # print(f"Unexpected error during Nmap subprocess: {e}. Falling back to basic scan.")
            pass # Fall through to basic scan
    
    # Fallback to Basic TCP Connect Scan if Nmap is not found or fails
    return _basic_port_scan_socket(hostname)
    
    # Fallback to Basic TCP Connect Scan
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080] 
    fallback_message = "Fallback used due to Nmap unavailability — Basic TCP scan"

    try:
        ip = socket.gethostbyname(hostname)
        for port in common_ports:
            try:
                with socket.create_connection((ip, port), timeout=1.5) as s: 
                    open_ports.append(f"{port}/tcp")
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
        
        return {"method": "basic", "open_ports": open_ports if open_ports else "None found", "message": fallback_message}
    except socket.gaierror:
        return {"error": "Could not resolve host for port scan.", "method": "basic", "message": fallback_message}
    except Exception as e:
        return {"error": f"Basic port scan failed unexpectedly: {e}", "method": "basic", "message": fallback_message}


# --- Wayback Machine Function ---
def get_wayback_snapshots(url):
    try:
        full_domain = urlparse(url).netloc or url
        def query_wayback(domain_to_check):
            res = requests.get("https://archive.org/wayback/available", params={"url": domain_to_check}, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
            res.raise_for_status()
            data = res.json()
            snapshot = data.get("archived_snapshots", {}).get("closest", {})
            if snapshot and snapshot.get("available"):
                return { "status": "Available", "url": snapshot.get("url"), "timestamp": snapshot.get("timestamp") }
            return None

        result = query_wayback(full_domain)
        if not result and full_domain.startswith('www.'):
            root_domain = full_domain.replace('www.', '', 1)
            result = query_wayback(root_domain)
        return result or {"status": "No snapshots found"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Error querying Wayback Machine: {e}. This might be a network issue or the service is down."}
    except Exception as e:
        return {"error": f"An unexpected error occurred with Wayback Machine: {e}"}

# --- Other Scanner Functions ---
def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        def format_date(date_data):
            if not date_data: return None
            if isinstance(date_data, list): return [d.isoformat() if hasattr(d, 'isoformat') else str(d) for d in date_data]
            return date_data.isoformat() if hasattr(date_data, 'isoformat') else str(date_data)

        registrar = domain_info.registrar if hasattr(domain_info, 'registrar') else None
        creation_date = format_date(domain_info.creation_date) if hasattr(domain_info, 'creation_date') else None
        expiration_date = format_date(domain_info.expiration_date) if hasattr(domain_info, 'expiration_date') else None
        name_servers = domain_info.name_servers if hasattr(domain_info, 'name_servers') else []
        if isinstance(name_servers, str): name_servers = [name_servers] 

        return { 
            "registrar": registrar, 
            "creation_date": creation_date, 
            "expiration_date": expiration_date, 
            "name_servers": name_servers 
        }
    except Exception as e:
        return {"error": f"Could not retrieve WHOIS info. Reason: {e}. The WHOIS service might be unavailable or rate-limiting."}

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r.to_text()).strip('"') for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            records[record_type] = [] 
        except Exception as e:
            records[record_type] = [f"Error: {e}"] 
    return records

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expires_dt = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                return { 
                    "issuer": dict(x[0] for x in cert.get('issuer', [])), 
                    "subject": dict(x[0] for x in cert.get('subject', [])), 
                    "expires": expires_dt.strftime('%Y-%m-%d %H:%M:%S %Z'), 
                    "expired": expires_dt < datetime.now() 
                }
    except ssl.SSLError as e:
        return {"error": f"SSL Certificate Error: {e}. The certificate might be invalid or misconfigured (e.g., hostname mismatch, untrusted issuer)."}
    except socket.timeout:
        return {"error": "SSL Handshake Timeout: The server did not respond in time on port 443 during SSL negotiation. This could be due to network issues or server load."}
    except ConnectionRefusedError:
        return {"error": "Connection Refused on Port 443: The server actively rejected the connection. This could mean no HTTPS service is running, a firewall is blocking access, or the server is down."}
    except Exception as e:
        return {"error": f"Could not retrieve SSL info due to an unexpected error: {e}"}

def analyze_cookies(response):
    cookies_data = []
    for cookie in response.cookies:
        flags = []
        if cookie.secure: flags.append('Secure')
        if cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'): flags.append('HttpOnly')
        if 'samesite' in cookie._rest: flags.append(f"SameSite={cookie._rest['samesite']}")
        cookies_data.append({ "name": cookie.name, "value": cookie.value, "domain": cookie.domain, "path": cookie.path, "expires": cookie.expires, "flags": flags })
    return cookies_data

def analyze_email_security(domain, dns_records):
    email_security = { 
        'spf': {'present': False, 'record': 'Not found'}, 
        'dmarc': {'present': False, 'record': 'Not found'} 
    }
    
    txt_records = dns_records.get('TXT', [])
    for record in txt_records:
        if isinstance(record, str) and record.lower().startswith('v=spf1'):
            email_security['spf']['present'] = True
            email_security['spf']['record'] = record
            break
            
    try:
        dmarc_answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_answers:
            dmarc_text = str(record.to_text()).strip('"')
            if dmarc_text.lower().startswith('v=dmarc1'):
                email_security['dmarc']['present'] = True
                email_security['dmarc']['record'] = dmarc_text
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        pass 
    except Exception as e:
        email_security['dmarc']['record'] = f"Error: {e}" 
        
    return email_security

# --- Master function to run all scans ---
def run_information_scan(url):
    full_url = url
    if not re.match(r'https?://', full_url): 
        full_url = 'https://' + url

    domain = get_domain_from_url(full_url)
    if not domain:
        return {"error": "Invalid URL provided.", "active_tests": [], "vulnerabilities": []}

    print(f"🔍 Starting information scan for domain: {domain}")

    scan_data = {
        "url": url, 
        "domain": domain,
        "timestamp": datetime.now().isoformat(), 
        "active_tests": [],
        "vulnerabilities": [], 
        "findings": [], 
        "recommendations": [], 
        
        "http_headers": {},
        "cookies": [],
        "tech_stack": {},
        "whois": {},
        "dns": {},
        "ssl": {},
        "email_security": {},
        "wayback": {},
        "port_scan": {},
        "subdomains": {},
        "js_libraries": [], 
    }

    # --- Initial HTTP Request & Basic Info Gathering ---
    scan_data['active_tests'].append({"test": "Initial HTTP Request & Basic Info", "status": "Performed"})
    try:
        http_response = requests.get(full_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15, allow_redirects=True)
        http_response.raise_for_status() 
        
        scan_data['http_headers'] = dict(http_response.headers)
        scan_data['cookies'] = analyze_cookies(http_response)
        scan_data['tech_stack'] = builtwith.parse(full_url) 
        
        expected_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"]
        headers_lower = {k.lower(): v for k, v in scan_data['http_headers'].items()}
        missing_headers = [h for h in expected_headers if h.lower() not in headers_lower]
        if missing_headers:
            scan_data["findings"].append(f"🛡️ Low: Missing security headers: {', '.join(missing_headers)}")
            for h in missing_headers:
                scan_data["recommendations"].append(f"Implement the {h} HTTP security header.")
        
    except requests.exceptions.RequestException as e:
        scan_data['http_headers'] = {"error": f"Could not fetch headers. Reason: {e}. Check URL or network."}
        scan_data['tech_stack'] = {"error": "Could not perform tech analysis."}
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: Initial HTTP request failed: {e}")
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: General error during initial HTTP request: {e}")


    # --- Individual Test Blocks with Error Logging for Active Tests ---

    # WHOIS Lookup
    scan_data['active_tests'].append({"test": "WHOIS Lookup", "status": "Performed"})
    try:
        whois_info = get_whois_info(domain)
        if "error" in whois_info:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: WHOIS lookup failed: {whois_info['error']}")
        scan_data['whois'] = whois_info
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: WHOIS lookup error: {e}")


    # DNS Records
    scan_data['active_tests'].append({"test": "DNS Records", "status": "Performed"})
    try:
        dns_records = get_dns_records(domain)
        if not dns_records.get('A') and not dns_records.get('AAAA'):
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: Could not resolve A/AAAA DNS records for {domain}.")
        scan_data['dns'] = dns_records
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: DNS records lookup error: {e}")


    # SSL Certificate
    scan_data['active_tests'].append({"test": "SSL Certificate", "status": "Performed"})
    try:
        ssl_info = get_ssl_info(domain)
        if "error" in ssl_info:
            scan_data['active_tests'][-1]['status'] = "Error"
            error_message = ssl_info['error']
            scan_data["findings"].append(f"⚠️ Warning: SSL Certificate check failed: {error_message}")
            
            vuln_summary = error_message
            vuln_recommendation = "Review server configuration for port 443 and SSL/TLS services. Ensure no firewalls are blocking access."
            vuln_severity = "High"

            if "Connection Refused" in error_message:
                vuln_summary = "SSL Connection Refused: No HTTPS service or firewall blocking port 443."
                vuln_recommendation = "Check if a web server is running and listening on HTTPS (port 443). Verify firewall rules (both server-side and network-level) are not blocking incoming connections on port 443."
                vuln_severity = "Critical" 
            elif "SSL Certificate Error" in error_message:
                vuln_summary = "SSL Certificate Invalid/Misconfigured: Certificate issues detected."
                vuln_recommendation = "Verify your SSL/TLS certificate is correctly installed, valid, and matches the domain. Ensure full chain is provided."
                vuln_severity = "High"
            elif "SSL Handshake Timeout" in error_message:
                vuln_summary = "SSL Handshake Timeout: Server unresponsive during SSL negotiation."
                vuln_recommendation = "Check server load, network connectivity, and SSL/TLS handshake configuration. Ensure the server is not overwhelmed."
                vuln_severity = "Medium" 

            scan_data['vulnerabilities'].append({
                "type": "SSL/TLS Issue",
                "severity": vuln_severity,
                "summary": vuln_summary,
                "recommendation": vuln_recommendation
            })
            scan_data["recommendations"].append(vuln_recommendation)

        elif ssl_info.get('expired'):
             scan_data["findings"].append(f"🚨 Critical: SSL Certificate expired on {ssl_info.get('expires')}.")
             scan_data['vulnerabilities'].append({ 
                "type": "Expired SSL Certificate",
                "severity": "Critical",
                "summary": f"SSL/TLS certificate expired on {ssl_info.get('expires')}",
                "recommendation": "Renew the SSL certificate immediately to maintain trust and security."
            })
             scan_data["recommendations"].append("Renew the SSL certificate immediately to maintain trust and security.")
        scan_data['ssl'] = ssl_info
    except Exception as e: 
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: SSL Certificate check experienced an unexpected error: {e}")
        scan_data['vulnerabilities'].append({
                "type": "SSL/TLS Issue",
                "severity": "High",
                "summary": f"Unexpected error during SSL check: {e}",
                "recommendation": "Investigate the server's SSL/TLS configuration and network connectivity."
            })
        scan_data["recommendations"].append("Investigate the server's SSL/TLS configuration and network connectivity.")


    # Email Security (SPF/DMARC)
    scan_data['active_tests'].append({"test": "Email Security (SPF/DMARC)", "status": "Performed"})
    try:
        email_security = analyze_email_security(domain, scan_data['dns'])
        if not email_security.get('spf', {}).get('present'):
            scan_data["findings"].append("🛡️ Low: Missing SPF record for email security.")
            scan_data['vulnerabilities'].append({
                "type": "Email Security Misconfiguration",
                "severity": "Low",
                "summary": "Sender Policy Framework (SPF) record is missing.",
                "recommendation": "Create a valid SPF record in your DNS settings to prevent email spoofing."
            })
        if not email_security.get('dmarc', {}).get('present'):
            scan_data["findings"].append("🛡️ Medium: Missing DMARC record for email security.")
            scan_data['vulnerabilities'].append({
                "type": "Email Security Misconfiguration",
                "severity": "Medium",
                "summary": "DMARC (Domain-based Message Authentication, Reporting, and Conformance) record is missing.",
                "recommendation": "Create a DMARC record and define a policy (e.g., p=quarantine) to protect against phishing and spoofing attacks."
            })
        scan_data['email_security'] = email_security
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: Email Security check error: {e}")


    # Wayback Snapshots
    scan_data['active_tests'].append({"test": "Wayback Snapshots", "status": "Performed"})
    try:
        wayback_data = get_wayback_snapshots(full_url)
        if "error" in wayback_data:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: Wayback Machine check failed: {wayback_data['error']}")
        elif wayback_data.get("status") == "Available":
             scan_data["findings"].append(f"📸 Info: Latest Wayback snapshot from {wayback_data.get('timestamp')}.")
        scan_data['wayback'] = wayback_data
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: Wayback Machine check error: {e}")


    # Port Scan (Calling the updated perform_port_scan)
    scan_data['active_tests'].append({"test": "Port Scan", "status": "Performed"})
    try:
        port_scan_results = perform_port_scan(domain) # Calls the updated function
        if "error" in port_scan_results:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: Port Scan failed: {port_scan_results['error']}")
            if port_scan_results.get('message'): # Also add specific fallback message if available
                 scan_data["findings"].append(f"ℹ️ {port_scan_results['message']}")
        elif port_scan_results.get('open_ports') != "None found" and port_scan_results.get('open_ports'):
            scan_data["findings"].append(f"🔌 Info: Open ports found via {port_scan_results.get('method', 'scan')} scan: {', '.join(port_scan_results['open_ports'])}")
            scan_data["recommendations"].append("Review all open ports. Ensure that only necessary ports are exposed to the internet and are properly firewalled.")
            if port_scan_results.get('message') and port_scan_results.get('method') == 'basic':
                 scan_data["findings"].append(f"ℹ️ {port_scan_results['message']}")
        scan_data['port_scan'] = port_scan_results # Store full port scan result
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: Port Scan error: {e}")


    # Subdomain Enumeration
    scan_data['active_tests'].append({"test": "Subdomain Enumeration", "status": "Performed"})
    try:
        subdomains_result = get_subdomains(domain)
        if "error" in subdomains_result:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: Subdomain enumeration failed: {subdomains_result['error']}")
        elif subdomains_result.get('subdomains'):
            sub_count = len(subdomains_result['subdomains'])
            preview = ", ".join(subdomains_result['subdomains'][:3]) + ("..." if sub_count > 3 else "")
            scan_data["findings"].append(f"🌐 Info: Found {sub_count} subdomains (e.g., {preview}).")
            scan_data["recommendations"].append("Review all discovered subdomains for potential security risks and unauthorized deployments.")
        scan_data['subdomains'] = subdomains_result
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: Subdomain enumeration error: {e}")


    # JavaScript Vulnerability Scan
    scan_data['active_tests'].append({"test": "JavaScript Vulnerability Scan", "status": "Performed"})
    try:
        js_analysis_result = analyze_js_libraries(scan_data['tech_stack'])
        if "error" in js_analysis_result:
            scan_data['active_tests'][-1]['status'] = "Error"
            scan_data["findings"].append(f"⚠️ Warning: JS Library scan failed: {js_analysis_result['error']}")
            scan_data['js_libraries'] = [{
                "library": "Error",
                "version": "N/A",
                "severity": "Error",
                "summary": f"Error during JS analysis: {js_analysis_result['error']}"
            }]
        else:
            for vuln_lib in js_analysis_result.get("vulnerable_libraries", []):
                scan_data['vulnerabilities'].append({
                    "type": "Vulnerable JS Library",
                    "severity": vuln_lib.get("severity", "Medium"),
                    "summary": f"{vuln_lib['library']} (v{vuln_lib['version']}): {vuln_lib['summary']}",
                    "recommendation": "Update vulnerable JavaScript libraries to their latest, patched versions."
                })
                scan_data["findings"].append(f"💻 {vuln_lib.get('severity', 'Medium')}: Vulnerable JS library found: {vuln_lib['library']} - {vuln_lib['summary']}")

            scan_data['js_libraries'] = js_analysis_result.get("all_identified_js_libs", [])
            
            if not scan_data['js_libraries'] and not js_analysis_result.get("vulnerable_libraries"):
                 scan_data['js_libraries'] = [{
                    "library": "N/A",
                    "version": "-",
                    "severity": "-",
                    "summary": "No JavaScript libraries identified or analyzed."
                }]
                 
    except Exception as e:
        scan_data['active_tests'][-1]['status'] = "Error"
        scan_data["findings"].append(f"⚠️ Warning: JS Library scan error: {e}")
        scan_data['js_libraries'] = [{
            "library": "Runtime Error",
            "version": "N/A",
            "severity": "Error",
            "summary": f"Unexpected runtime error during JS scan: {e}"
        }]


    # Final check for findings
    if not scan_data["findings"] and not scan_data["vulnerabilities"]:
        scan_data["findings"].append("✅ No immediate low-hanging vulnerabilities or informational items were found.")

    # Deduplicate recommendations at the end
    scan_data["recommendations"] = sorted(list(set(scan_data["recommendations"])))

    print("✅ Information Scan complete.")
    return scan_data