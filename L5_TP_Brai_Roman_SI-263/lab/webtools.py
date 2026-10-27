"""Instrumente reutilizabile pentru raportarea stării unui site web."""

import hashlib
import json
import socket
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests


TIMEOUT = 10
DEFAULT_HEADERS = {"User-Agent": "Brai-Roman-SI-263"}
SECURITY_HEADER_NAMES = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)


def fetch(url: str, timeout: float = TIMEOUT) -> requests.Response:
    """Descarcă un URL folosind antetele implicite ale modulului."""
    return requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)


def get_status(url: str) -> int:
    """Returnează codul HTTP al URL-ului."""
    return fetch(url).status_code


def get_title(html: str) -> str:
    """Extrage titlul unei pagini HTML sau returnează șirul gol."""
    lower_html = html.lower()
    start = lower_html.find("<title>")
    end = lower_html.find("</title>", start + 7)
    if start == -1 or end == -1:
        return ""
    return html[start + len("<title>") : end].strip()


def get_header(url: str, name: str, default: str = "lipsește") -> str:
    """Returnează un antet HTTP sau valoarea implicită."""
    return fetch(url).headers.get(name, default)


def check_paths(base: str, paths: list[str]) -> dict[str, int | None]:
    """Verifică mai multe căi și respectă pauza dintre cereri."""
    results: dict[str, int | None] = {}
    for index, path in enumerate(paths):
        if index:
            time.sleep(1)
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        try:
            results[path] = get_status(url)
        except requests.RequestException:
            results[path] = None
    return results


def security_headers(url: str) -> dict[str, bool]:
    """Returnează prezența antetelor de securitate cerute."""
    response = fetch(url)
    return {name: name in response.headers for name in SECURITY_HEADER_NAMES}


def score_headers(results: dict[str, bool]) -> str:
    """Returnează scorul antetelor în forma prezent/total."""
    return f"{sum(results.values())}/{len(results)}"


def fetch_robots(base: str) -> str | None:
    """Returnează robots.txt sau None dacă nu poate fi citit."""
    try:
        response = fetch(urljoin(base.rstrip("/") + "/", "robots.txt"))
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return None


def disallowed_paths(robots_text: str | None) -> list[str]:
    """Extrage căile Disallow din textul robots.txt."""
    if not robots_text:
        return []
    result = []
    for line in robots_text.splitlines():
        field, separator, value = line.partition(":")
        if separator and field.strip().lower() == "disallow" and value.strip():
            result.append(value.strip())
    return result


def response_times(*urls: str) -> dict[str, float | None]:
    """Măsoară în secunde durata fiecărei cereri."""
    result: dict[str, float | None] = {}
    for index, url in enumerate(urls):
        if index:
            time.sleep(1)
        start = time.perf_counter()
        try:
            fetch(url)
            result[url] = time.perf_counter() - start
        except requests.RequestException:
            result[url] = None
    return result


def log(message: str, **details: Any) -> None:
    """Afișează un mesaj și detalii nume=valoare."""
    print(message + "".join(f" | {name}={value}" for name, value in details.items()))


def resolve(hostname: str) -> str:
    """Returnează adresa IPv4 a domeniului."""
    return socket.gethostbyname(hostname)


def cert_days_left(hostname: str) -> int:
    """Returnează zilele întregi rămase până la expirarea certificatului TLS."""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            certificate = secure_sock.getpeercert()
    if certificate is None:
        raise ValueError("Certificatul TLS nu a putut fi citit.")
    not_after = certificate.get("notAfter")
    if not isinstance(not_after, str):
        raise ValueError("Certificatul TLS nu conține data expirării.")
    expiry = ssl.cert_time_to_seconds(not_after)
    return max(0, int((expiry - time.time()) // 86400))


def page_fingerprint(url: str) -> str:
    """Returnează SHA-256 pentru corpul paginii."""
    response = fetch(url)
    response.raise_for_status()
    return hashlib.sha256(response.content).hexdigest()


def extract_links(html: str) -> list[str]:
    """Extrage href-urile fără duplicate folosind parserul BeautifulSoup dacă există."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        import re

        return list(dict.fromkeys(re.findall(r'href=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)))
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if isinstance(href, str):
            links.append(href)
    return list(dict.fromkeys(links))


def split_links(links: list[str], base_url: str) -> tuple[list[str], list[str]]:
    """Separă legăturile interne și externe și le normalizează ca URL-uri absolute."""
    domain = urlparse(base_url).netloc.lower()
    internal: list[str] = []
    external: list[str] = []
    for link in links:
        absolute = urljoin(base_url, link)
        if urlparse(absolute).netloc.lower() == domain:
            internal.append(absolute)
        else:
            external.append(absolute)
    return internal, external


def redirect_chain(url: str) -> tuple[list[dict[str, Any]], str]:
    """Urmărește redirecționările de la varianta HTTP a URL-ului."""
    parsed = urlparse(url)
    http_url = parsed._replace(scheme="http").geturl()
    response = fetch(http_url)
    chain = [{"status": item.status_code, "url": item.url} for item in response.history]
    return chain, response.url


def site_report(url: str, output_file: str = "report.json") -> dict[str, Any]:
    """Colectează, afișează și salvează raportul complet al site-ului."""
    response = fetch(url)
    response.raise_for_status()
    final_url = response.url
    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""

    headers_result = {name: name in response.headers for name in SECURITY_HEADER_NAMES}
    links = extract_links(response.text)
    internal, external = split_links(links, final_url)

    time.sleep(1)
    robots = fetch_robots(final_url)
    time.sleep(1)
    redirects, redirected_to = redirect_chain(final_url)

    report: dict[str, Any] = {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "status_code": response.status_code,
        "final_url": final_url,
        "title": get_title(response.text),
        "ip_address": resolve(hostname),
        "redirects": redirects,
        "http_final_url": redirected_to,
        "security_headers": headers_result,
        "security_score": score_headers(headers_result),
        "certificate_days_left": cert_days_left(hostname),
        "internal_links_count": len(internal),
        "external_links_count": len(external),
        "disallowed_paths": disallowed_paths(robots),
    }

    path = Path(output_file)
    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print(f"=== Raport site: {url} ===")
    print("Cod de stare:     ", report["status_code"])
    print("URL final:         ", report["final_url"])
    print("Titlu:             ", report["title"])
    print("Adresă IP:         ", report["ip_address"])
    redirect_text = " -> ".join(str(item["status"]) for item in redirects) or "fără redirecționări"
    print("Redirecționări:    ", redirect_text, "->", redirected_to)
    print("Scor securitate:   ", report["security_score"])
    print("Certificat:        ", report["certificate_days_left"], "zile rămase")
    print("Legături:          ", len(internal), "interne,", len(external), "externe")
    print("Căi interzise:     ", ", ".join(report["disallowed_paths"]) or "niciuna")
    print("Salvat în", path)
    return report


if __name__ == "__main__":
    print("Autotest:", get_status("https://cybercor.org"))
