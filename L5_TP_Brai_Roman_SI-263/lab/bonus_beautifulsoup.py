"""Rezolvarea exercițiului bonus cu BeautifulSoup."""

from bs4 import BeautifulSoup


def get_title(html: str) -> str:
    """Extrage sigur titlul paginii folosind parserul HTML."""
    soup = BeautifulSoup(html, "html.parser")
    return soup.title.get_text(strip=True) if soup.title else ""


def extract_links(html: str) -> list[str]:
    """Extrage toate legăturile href fără duplicate."""
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if isinstance(href, str):
            links.append(href)
    return list(dict.fromkeys(links))
