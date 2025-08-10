import requests
import time

# Function to add colors (optional)
def color(text, code):
    return f"\033[{code}m{text}\033[0m"

def check_clickjacking(url):
    try:
        print(f"\n[🔍] Checking Clickjacking protection for: {url}")
        
        start_time = time.time()
        response = requests.get(url)
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        # Print all response headers
        print("\n📥 Response Headers from the server:")
        for header, value in response.headers.items():
            print(f"{color(header, '94')}: {color(value, '92')}")
        
        print(f"\n⏱️ Time taken for the request: {color(f'{elapsed_time:.3f} seconds', '96')}")

        print("\n🔎 Clickjacking Protection Check:")

        # Check for X-Frame-Options
        if 'X-Frame-Options' in response.headers:
            xfo_value = response.headers['X-Frame-Options']
            print(f"[✓] X-Frame-Options header is present.")
            print(f"[+] Value: {xfo_value}")
            print("[✅] Website is protected from Clickjacking.")
        else:
            print("[!] X-Frame-Options header is missing!")

        # Check for Content-Security-Policy
        if 'Content-Security-Policy' in response.headers:
            csp_value = response.headers['Content-Security-Policy']
            print(f"\n[✓] Content-Security-Policy header is present.")
            print(f"[+] Value: {csp_value}")
            if "frame-ancestors" in csp_value:
                print("[✅] CSP includes frame-ancestors directive (protection against Clickjacking).")
            else:
                print("[⚠️] CSP does not include frame-ancestors directive.")
        else:
            print("\n[!] Content-Security-Policy header is missing!")

        # Final remark
        if 'X-Frame-Options' not in response.headers and 'Content-Security-Policy' not in response.headers:
            print("[❌] Website is likely vulnerable to Clickjacking.")
        else:
            print("[🔐] At least one protection mechanism is in place.")

    except requests.exceptions.RequestException as e:
        print("[✗] Error while connecting to the website.")
        print("Details:", e)

# Entry point
if __name__ == "__main__":
    target_url = input("Enter the target URL (with http:// or https://): ").strip()
    if target_url:
        check_clickjacking(target_url)
    else:
        print("[✗] No URL entered.")
