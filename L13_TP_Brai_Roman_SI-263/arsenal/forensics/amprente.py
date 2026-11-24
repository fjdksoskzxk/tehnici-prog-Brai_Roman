"""Detectează tipul și calculează amprenta fișierelor de probă."""

from __future__ import annotations

import argparse
import hashlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import TypedDict


MAGIC = {b"\x89PNG": "PNG", b"%PDF": "PDF", b"PK\x03\x04": "ZIP"}


class FisaFisier(TypedDict):
    nume: str
    tip: str
    sha256: str


def tip(head: bytes) -> str:
    """Întoarce tipul determinat din semnătura aflată la începutul datelor."""
    for semnatura, nume in MAGIC.items():
        if head.startswith(semnatura):
            return nume
    return "necunoscut"


def amprenta_fisier(cale: str | os.PathLike[str]) -> FisaFisier:
    """Citește binar un fișier și întoarce tipul și SHA-256 prescurtat."""
    with open(cale, "rb") as fisier:
        date = fisier.read()
    return {
        "nume": os.path.basename(cale),
        "tip": tip(date[:8]),
        "sha256": hashlib.sha256(date).hexdigest()[:16],
    }


def scaneaza(folder: str | os.PathLike[str]) -> list[FisaFisier]:
    """Amprentează, în ordine alfabetică, toate fișierele din folder."""
    rezultate: list[FisaFisier] = []
    for nume in sorted(os.listdir(folder)):
        cale = os.path.join(folder, nume)
        if os.path.isfile(cale):
            rezultate.append(amprenta_fisier(cale))
    return rezultate


def amprente_lenes(folder: str | os.PathLike[str]) -> Iterator[FisaFisier]:
    """Produce câte o fișă la cerere, fără a păstra lista completă în memorie."""
    for nume in sorted(os.listdir(folder)):
        cale = os.path.join(folder, nume)
        if os.path.isfile(cale):
            yield amprenta_fisier(cale)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detectează tipul și calculează SHA-256 pentru fișiere."
    )
    parser.add_argument("folder", type=Path, help="folderul cu fișierele de examinat")
    argumente = parser.parse_args(argv)

    if not argumente.folder.is_dir():
        parser.error(f"folder inexistent: {argumente.folder}")

    for fisa in scaneaza(argumente.folder):
        print(f"{fisa['nume']:14} {fisa['tip']:11} {fisa['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
