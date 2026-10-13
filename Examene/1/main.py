def build_url(host, path):
    return "https://" + host + "/" + path.lstrip("/")


def is_https(url):
    return url.startswith("https://")


# Testare
print(build_url("example.com", "login"))
print(build_url("example.com", "/login"))

print(is_https("https://example.com"))
print(is_https("http://example.com"))

# Partea 2

import requests

def show_response(url):
    r = requests.get(url)
    print("Status:", r.status_code)
    print("Content-Type:", r.headers.get("Content-Type"))


# Testare
show_response("https://example.com")

# Partea 3

import requests

def check_site(url):
    try:
        r = requests.get(url, timeout=5)

        return {
            "status": r.status_code,
            "content_type": r.headers.get("Content-Type", "unknown"),
            "length": len(r.content),
            "server": r.headers.get("Server", "unknown")
        }

    except requests.exceptions.RequestException as e:
        return {
            "status": None,
            "error": str(e)
        }
SITES = [
"https://example.com",
"https://httpbin.org/html",
"https://httpbin.org/json",
"https://httpbin.org/status/200",
"https://httpbin.org/redirect/1",
"https://httpbin.org/delay/2",
]

# Testare pe toate site-urile
for url in SITES:
    print(url, check_site(url))
### Partea 4: Verificarea mai multor site-uri.

import requests

def scan_sites():
    results = []

    for url in SITES:
        result = check_site(url)
        results.append((url, result))

    successful = []

    for url, result in results:
        if result["status"] == 200:
            successful.append((url, result))

    successful.sort(
        key=lambda x: x[1]["length"],
        reverse=True
    )

    for url, result in successful:
        print(f'{url} -> 200, {result["length"]} octeți')

    print(f"Reușite: {len(successful)} | Eșuate: {len(results) - len(successful)}")

SITES = [
"https://example.com",
"https://httpbin.org/html",
"https://httpbin.org/json",
"https://httpbin.org/status/200",
"https://httpbin.org/redirect/1",
"https://httpbin.org/delay/2",
]
    

# Testare
scan_sites()
    
    ### Partea 5
    
import requests
    
def check_headers(url):
        try:
            response = requests.get(url)
            present_headers = [header for header in SECURITY_HEADERS if header in response.headers]
            missing_headers = [header for header in SECURITY_HEADERS if header not in response.headers]
            score = len(present_headers) / len(SECURITY_HEADERS) * 100
            return {
                "present": present_headers,
                "missing": missing_headers,
                "score": score
            }
        except requests.RequestException as e:
            print(f"Eroare la accesarea site-ului {url}: {e}")
            return {
                "present": [],
                "missing": SECURITY_HEADERS,
                "score": 0
            }   
            
    
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

### Partea 6

import requests

def retry_check(url, attempts=3):
    status = None
    error = None
    count = 0

    for i in range(attempts):
        count += 1

        try:
            r = requests.get(url, timeout=5)
            status = r.status_code
            error = None

            if status < 500:
                break

        except requests.exceptions.RequestException as e:
            error = str(e)

    result = {
        "status": status,
        "attempts": count
    }

    if status is None and error is not None:
        result["error"] = error

    return result


print(retry_check("https://httpbin.org/status/200"))
print(retry_check("https://httpbin.org/status/404"))
print(retry_check("https://httpbin.org/status/500"))
print(retry_check("https://httpbin.org/status/500", attempts=2))
print(retry_check("http://this-site-does-not-exist.invalid"))

    

    
