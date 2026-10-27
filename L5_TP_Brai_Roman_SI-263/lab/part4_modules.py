"""Rezolvarea exercițiilor 35-43 cu module din biblioteca standard."""

import hashlib
import json
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests


BASE_URL = "https://cybercor.org"
TIMEOUT = 10


def parse_url(url: str) -> dict[str, str]:
    """Descompune URL-ul în componentele cerute."""
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


def build_urls(base: str, links: list[str]) -> list[str]:
    """Transformă legăturile relative în URL-uri absolute."""
    return [urljoin(base.rstrip("/") + "/", link) for link in links]


def extract_links(html: str) -> list[str]:
    """Extrage fără duplicate valorile href scrise cu ghilimele duble."""
    return list(dict.fromkeys(re.findall(r'href="([^"]+)"', html, flags=re.IGNORECASE)))


def split_links(links: list[str], domain: str) -> tuple[list[str], list[str]]:
    """Separă legăturile absolute în interne și externe."""
    normalized_domain = urlparse(domain if "://" in domain else "https://" + domain).netloc.lower()
    base = "https://" + normalized_domain + "/"
    internal: list[str] = []
    external: list[str] = []
    for link in links:
        absolute = urljoin(base, link)
        if urlparse(absolute).netloc.lower() == normalized_domain:
            internal.append(absolute)
        else:
            external.append(absolute)
    return internal, external


class ImageFinder(HTMLParser):
    """Colectează atributele src ale tagurilor img."""

    def __init__(self) -> None:
        """Inițializează lista de imagini."""
        super().__init__()
        self.images: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Adaugă src când parserul întâlnește un tag img."""
        if tag.lower() == "img":
            src = dict(attrs).get("src")
            if src:
                self.images.append(src)


def find_images(html: str) -> list[str]:
    """Rulează ImageFinder și returnează imaginile găsite."""
    finder = ImageFinder()
    finder.feed(html)
    return finder.images


def page_fingerprint(url: str) -> str:
    """Returnează amprenta SHA-256 a corpului răspunsului."""
    response = requests.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return hashlib.sha256(response.content).hexdigest()


def save_and_load_headers(url: str, filename: str = "headers.json") -> dict[str, str]:
    """Salvează antetele în JSON, apoi le încarcă și le returnează."""
    response = requests.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    path = Path(filename)
    with path.open("w", encoding="utf-8") as file:
        json.dump(dict(response.headers), file, indent=2, ensure_ascii=False)
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def resolve(hostname: str) -> str:
    """Returnează adresa IPv4 rezolvată pentru hostname."""
    return socket.gethostbyname(hostname)


def cert_days_left(hostname: str) -> int:
    """Returnează numărul întreg de zile până la expirarea certificatului TLS."""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            certificate = secure_sock.getpeercert()
    if certificate is None:
        raise ValueError("Serverul nu a furnizat un certificat TLS")
    not_after = certificate.get("notAfter")
    if not isinstance(not_after, str):
        raise ValueError("Certificatul TLS nu conține o dată de expirare validă")
    expires_at = ssl.cert_time_to_seconds(not_after)
    return max(0, int((expires_at - time.time()) // 86400))


def main() -> None:
    """Rulează exemplele pentru exercițiile 35-43."""
    print("Ex. 35 -", parse_url("https://cybercor.org/path?x=1#top"))
    print("Ex. 36 -", build_urls(BASE_URL, ["/about", "contact.html", "../index.html"]))

    response = requests.get(BASE_URL, timeout=TIMEOUT)
    response.raise_for_status()
    links = extract_links(response.text)
    print("Ex. 37 - legături:", links)
    internal, external = split_links(links, "cybercor.org")
    print("Ex. 38 - interne:", len(internal), "externe:", len(external))

    test_html = """
    <html><body>
      <img src="/logo.png" alt="Logo">
      <IMG SRC="poza.jpg">
      <img alt="imagine fără src">
      <img src="https://cdn.example.com/banner.webp" />
      <a href="/despre">Aceasta nu este o imagine</a>
    </body></html>
    """
    expected = ["/logo.png", "poza.jpg", "https://cdn.example.com/banner.webp"]
    images = find_images(test_html)
    print("Ex. 39 - test:", images)
    assert images == expected, "Parserul nu a găsit exact imaginile așteptate"
    real_images = find_images(response.text)
    print("Imagini reale:", len(real_images), real_images)
    print("Control <img:", response.text.lower().count("<img"))
    # HTMLParser.feed() apelează automat handle_starttag() în timpul parsării.

    time.sleep(1)
    first_hash = page_fingerprint(BASE_URL)
    time.sleep(1)
    second_hash = page_fingerprint(BASE_URL)
    print("Ex. 40 -", first_hash, second_hash, "identice=", first_hash == second_hash)
    # Amprentele diferă dacă serverul trimite conținut diferit între cereri.

    time.sleep(1)
    headers = save_and_load_headers(BASE_URL)
    print("Ex. 41 - Content-Type:", headers.get("Content-Type", "lipsește"))
    print("Ex. 42 - IP:", resolve("cybercor.org"))
    print("Ex. 43 - zile certificat:", cert_days_left("cybercor.org"))
    print("handle_starttag este apelată de HTMLParser în timpul feed().")


if __name__ == "__main__":
    main()
