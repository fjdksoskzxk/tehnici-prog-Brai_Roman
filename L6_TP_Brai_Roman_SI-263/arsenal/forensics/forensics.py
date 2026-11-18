"""Analiză de fișiere: semnături, strings, EXIF/GPS și file carving."""

from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

from PIL import Image
from PIL.ExifTags import TAGS


def tip_real(cale: str | Path) -> str:
    cap = Path(cale).read_bytes()[:8]
    semnaturi = [
        (b"%PDF", "pdf"),
        (b"\x89PNG", "png"),
        (b"\xff\xd8", "jpeg"),
        (b"PK\x03\x04", "zip/docx"),
    ]
    for semnatura, nume in semnaturi:
        if cap.startswith(semnatura):
            return nume
    return f"necunoscut ({cap.hex()})"


def extrage_strings(cale: str | Path, minim: int = 4) -> list[str]:
    date = Path(cale).read_bytes()
    expresie = rb"[ -~]{" + str(minim).encode() + rb",}"
    return [match.decode("ascii") for match in re.findall(expresie, date)]


def _decimal(valori: Any, referinta: str) -> float:
    grade, minute, secunde = (float(x) for x in valori)
    rezultat = grade + minute / 60 + secunde / 3600
    return -rezultat if referinta in ("S", "W") else rezultat


def exif_si_gps(cale: str | Path) -> dict[str, object]:
    exif = Image.open(cale).getexif()
    rezultat = {TAGS.get(tag, str(tag)): value for tag, value in exif.items() if tag != 0x8825}
    gps = exif.get_ifd(0x8825)
    if gps:
        lat = _decimal(gps[2], gps[1])
        lon = _decimal(gps[4], gps[3])
        rezultat["GPSDecimal"] = {"latitudine": round(lat, 6), "longitudine": round(lon, 6)}
    return rezultat


def carve_zip(cale: str | Path, iesire: str | Path) -> dict[str, object]:
    date = Path(cale).read_bytes()
    pozitie = date.find(b"PK\x03\x04")
    if pozitie < 0:
        raise ValueError("Semnătura ZIP nu a fost găsită")
    iesire = Path(iesire)
    iesire.write_bytes(date[pozitie:])
    with zipfile.ZipFile(iesire) as arhiva:
        fisiere = arhiva.namelist()
        arhiva.extractall(iesire.with_suffix(""))
    return {"offset": pozitie, "arhiva": str(iesire), "fisiere": fisiere}


def analizeaza(probe: Path, iesire: Path) -> dict[str, object]:
    rezultat = {
        "tip_foto": tip_real(probe / "foto.jpg"),
        "tip_ascuns": tip_real(probe / "ascuns.png"),
        "strings_relevante": [s for s in extrage_strings(probe / "ascuns.png") if "secret" in s.lower() or "FLAG" in s],
        "exif": exif_si_gps(probe / "foto.jpg"),
        "carving": carve_zip(probe / "ascuns.png", iesire / "gasit.zip"),
    }
    (iesire / "forensics_results.json").write_text(
        json.dumps(rezultat, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    return rezultat


def main() -> None:
    reconfigure_stdout = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure_stdout):
        reconfigure_stdout(encoding="utf-8")
    radacina = Path(__file__).resolve().parents[2]
    rezultat = analizeaza(radacina / "probe", radacina)
    print(json.dumps(rezultat, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
