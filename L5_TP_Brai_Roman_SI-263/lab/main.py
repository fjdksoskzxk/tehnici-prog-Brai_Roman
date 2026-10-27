"""Programul principal pentru exercițiile 44-50."""

import argparse
import csv
import time
from datetime import datetime
from pathlib import Path

import webtools
from webtools import DEFAULT_HEADERS, check_paths, get_title, security_headers, site_report


BASE_URL = "https://cybercor.org"


def save_path_report_csv(base: str, filename: str = "report.csv") -> Path:
    """Salvează rezultatele pentru căile standard într-un fișier CSV."""
    paths = ["/", "/robots.txt", "/sitemap.xml"]
    results = check_paths(base, paths)
    output = Path(filename)
    checked_at = datetime.now().isoformat()
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["path", "status", "checked_at"])
        writer.writeheader()
        for path, status in results.items():
            writer.writerow({"path": path, "status": status, "checked_at": checked_at})
    return output


def parse_arguments() -> argparse.Namespace:
    """Citește URL-ul opțional din linia de comandă."""
    parser = argparse.ArgumentParser(description="Generează un raport pentru site-ul laboratorului.")
    parser.add_argument("url", nargs="?", default=BASE_URL, help="URL-ul verificat")
    return parser.parse_args()


def main() -> None:
    """Generează report.json și report.csv pentru URL-ul primit."""
    args = parse_arguments()
    print("DEFAULT_HEADERS:", DEFAULT_HEADERS)
    # Ex. 44: acces prin numele modulului.
    preview = webtools.fetch(args.url)
    print("Titlu prin import webtools:", webtools.get_title(preview.text))
    # Ex. 45: acces direct la numele importate. Dacă am defini aici o altă
    # funcție get_title, numele local ar masca funcția importată.
    print("Titlu prin from webtools import get_title:", get_title(preview.text))
    time.sleep(1)
    print("Antete de securitate:", security_headers(args.url))
    time.sleep(1)
    site_report(args.url, "report.json")
    csv_path = save_path_report_csv(args.url, "report.csv")
    print("Salvat în", csv_path)


if __name__ == "__main__":
    main()
