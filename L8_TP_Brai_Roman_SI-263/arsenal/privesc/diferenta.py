"""Compara SUID-urile curente cu baza unui sistem curat."""

from __future__ import annotations

import os
import sys

if __package__ in (None, ""):
    director_script = os.path.dirname(os.path.abspath(__file__))
    sys.path = [cale for cale in sys.path if os.path.abspath(cale) != director_script]
    sys.path.insert(0, os.path.dirname(os.path.dirname(director_script)))

import argparse
from pathlib import Path

from arsenal.privesc.enum import GTFO, citeste_linii, nume


def cai(fisier: str | Path) -> set[str]:
    """Intoarce multimea cailor dintr-un fisier."""
    return set(citeste_linii(fisier))


def analizeaza(director: str | Path) -> dict[str, object]:
    """Calculeaza fisierele noi si riscul lor."""
    baza_dir = Path(director)
    baza = cai(baza_dir / "baza_suid.txt")
    acum = cai(baza_dir / "suid.txt")
    noi = acum - baza
    risc = {nume(cale): ("mare" if nume(cale) in GTFO else "normal") for cale in noi}
    periculoase = [cale for cale in sorted(noi) if nume(cale) in GTFO]
    return {
        "baza": baza,
        "acum": acum,
        "noi": noi,
        "risc": risc,
        "periculoase": periculoase,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Diferenta SUID fata de sistemul curat")
    parser.add_argument(
        "capturi",
        nargs="?",
        type=Path,
        default=Path(__file__).with_name("start"),
        help="folderul cu baza_suid.txt si suid.txt",
    )
    argumente = parser.parse_args()
    rezultat = analizeaza(argumente.capturi)

    baza = rezultat["baza"]
    acum = rezultat["acum"]
    noi = rezultat["noi"]
    assert isinstance(baza, set) and isinstance(acum, set) and isinstance(noi, set)

    print(f"baza: {len(baza)}  acum: {len(acum)}")
    print(f"{len(noi)} SUID noi fata de sistemul curat")
    for cale in sorted(noi):
        print(f"  {cale}")
    print(f"risc: {rezultat['risc']}")
    print(f"periculoase NOI: {rezultat['periculoase']}")


if __name__ == "__main__":
    main()

