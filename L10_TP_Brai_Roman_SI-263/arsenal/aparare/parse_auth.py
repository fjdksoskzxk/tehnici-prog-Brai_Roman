"""Extrage si numara esecurile de autentificare dintr-un jurnal SSH."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Iterable


TIPAR = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port"
)


def esec(linie: str) -> tuple[str, str] | None:
    """Intoarce perechea (utilizator, IP) sau None pentru un rand nerelevant."""
    potrivire = TIPAR.search(linie)
    if potrivire is None:
        return None
    return potrivire.group(1), potrivire.group(2)


def citeste_esecuri(cale: str | Path) -> list[dict[str, str]]:
    """Citeste jurnalul si intoarce esecurile fara a ceda la randuri stricate."""
    rezultate: list[dict[str, str]] = []
    try:
        fisier = open(cale, encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError) as eroare:
        print(f"nu pot citi {cale}: {eroare}")
        return rezultate

    with fisier:
        for linie in fisier:
            rezultat = esec(linie)
            if rezultat is not None:
                user, ip = rezultat
                rezultate.append({"user": user, "ip": ip})
    return rezultate


def pe_ip(esecuri: Iterable[dict[str, str]]) -> Counter[str]:
    """Intoarce numarul de esecuri pentru fiecare adresa IP."""
    return Counter(inregistrare["ip"] for inregistrare in esecuri)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Numara esecurile de autentificare din auth.log."
    )
    parser.add_argument("log", help="calea catre jurnalul auth.log")
    argumente = parser.parse_args(argv)

    esecuri = citeste_esecuri(argumente.log)
    numaratoare = pe_ip(esecuri)

    print(f"Esecuri de autentificare: {len(esecuri)}")
    for ip, numar in numaratoare.most_common():
        print(f"  {ip}: {numar}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
