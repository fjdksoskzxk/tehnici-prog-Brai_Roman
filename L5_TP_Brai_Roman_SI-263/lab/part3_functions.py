"""Rezolvarea exercițiilor 21-34 despre funcții."""

import time
from typing import Any

import requests


BASE_URL = "https://cybercor.org"
TIMEOUT = 10
SECURITY_HEADER_NAMES = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)


def fetch(url: str, timeout: float = 10) -> requests.Response:
    """Descarcă URL-ul și returnează obiectul Response."""
    return requests.get(url, timeout=timeout)


def get_status(url: str) -> int:
    """Returnează codul de stare HTTP pentru URL."""
    return fetch(url, timeout=TIMEOUT).status_code


def get_title(html: str) -> str:
    """Extrage titlul dintr-un șir HTML sau returnează șirul gol."""
    lower_html = html.lower()
    start_tag = lower_html.find("<title>")
    end_tag = lower_html.find("</title>", start_tag + 7)
    if start_tag == -1 or end_tag == -1:
        return ""
    return html[start_tag + len("<title>") : end_tag].strip()


def page_exists(url: str) -> bool:
    """Returnează True pentru un răspuns fără eroare și False la orice eroare de cerere."""
    try:
        response = fetch(url, timeout=TIMEOUT)
        response.raise_for_status()
        return True
    except (requests.RequestException, TypeError, ValueError):
        return False


def check_paths(base: str, paths: list[str]) -> dict[str, int | None]:
    """Returnează codurile de stare pentru căile date, cu pauză între cereri."""
    results: dict[str, int | None] = {}
    for index, path in enumerate(paths):
        if index:
            time.sleep(1)
        try:
            results[path] = get_status(base.rstrip("/") + "/" + path.lstrip("/"))
        except requests.RequestException:
            results[path] = None
    return results


def get_header(url: str, name: str, default: str = "lipsește") -> str:
    """Returnează un singur antet HTTP sau valoarea implicită."""
    response = fetch(url, timeout=TIMEOUT)
    return response.headers.get(name, default)


def security_headers(url: str) -> dict[str, bool]:
    """Verifică prezența celor cinci antete de securitate cerute."""
    response = fetch(url, timeout=TIMEOUT)
    return {name: name in response.headers for name in SECURITY_HEADER_NAMES}


def score_headers(results: dict[str, bool]) -> str:
    """Transformă rezultatele antetelor într-un scor de forma prezent/total."""
    return f"{sum(results.values())}/{len(results)}"


def fetch_robots(base: str) -> str | None:
    """Returnează robots.txt sau None dacă resursa nu există ori cererea eșuează."""
    try:
        response = fetch(base.rstrip("/") + "/robots.txt", timeout=TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return None


def disallowed_paths(robots_text: str | None) -> list[str]:
    """Extrage valorile directivelor Disallow din robots.txt."""
    if robots_text is None:
        return []
    paths = []
    for line in robots_text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "disallow" and value.strip():
            paths.append(value.strip())
    return paths


def response_times(*urls: str) -> dict[str, float | None]:
    """Măsoară timpul total al cererii pentru fiecare URL."""
    results: dict[str, float | None] = {}
    for index, url in enumerate(urls):
        if index:
            time.sleep(1)
        start = time.perf_counter()
        try:
            fetch(url, timeout=TIMEOUT)
            results[url] = time.perf_counter() - start
        except requests.RequestException:
            results[url] = None
    return results


def log(message: str, **details: Any) -> None:
    """Afișează mesajul urmat de detalii în forma nume=valoare."""
    suffix = "".join(f" | {name}={value}" for name, value in details.items())
    print(message + suffix)


def main() -> None:
    """Rulează exemplele cerute în exercițiile 21-34."""
    response = fetch(BASE_URL)
    print("Ex. 21 - status:", response.status_code)

    for index, path in enumerate(("/", "/robots.txt", "/sitemap.xml")):
        if index:
            time.sleep(1)
        print("Ex. 22 -", path, get_status(BASE_URL.rstrip("/") + path))

    time.sleep(1)
    print("Ex. 23 - timeout implicit:", fetch(BASE_URL).status_code)
    time.sleep(1)
    print("Ex. 23 - timeout=3:", fetch(BASE_URL, timeout=3).status_code)

    print("Ex. 24 - titlu:", get_title(response.text))
    print("Ex. 25 - help(get_title):")
    help(get_title)

    # Ex. 26: adnotările nu validează automat tipurile la rulare.
    try:
        print(get_status(123))  # type: ignore[arg-type]
    except (requests.RequestException, TypeError, ValueError) as error:
        print("Ex. 26 - type hints nu opresc apelul; biblioteca ridică:", type(error).__name__)

    print("Ex. 27 - domeniu invalid:", page_exists("https://this-domain-does-not-exist.invalid"))
    time.sleep(1)
    paths = ["/", "/robots.txt", "/sitemap.xml"]
    print("Ex. 28 -", check_paths(BASE_URL, paths))
    time.sleep(1)
    print("Ex. 29 - Server:", get_header(BASE_URL, name="Server"))
    time.sleep(1)
    headers = security_headers(BASE_URL)
    print("Ex. 30 -", headers)
    print("Ex. 31 -", score_headers(headers))
    time.sleep(1)
    print("Ex. 32 - Disallow:", disallowed_paths(fetch_robots(BASE_URL)))
    time.sleep(1)
    print("Ex. 33 -", response_times(BASE_URL, BASE_URL + "/robots.txt"))
    log("verificat", url=BASE_URL, status=response.status_code)

    # Verificați-vă: print produce un efect vizibil în funcție; return trimite
    # valoarea apelantului, care o poate salva, testa sau prelucra ulterior.
    print("print afișează; return oferă valoarea apelantului.")


if __name__ == "__main__":
    main()
