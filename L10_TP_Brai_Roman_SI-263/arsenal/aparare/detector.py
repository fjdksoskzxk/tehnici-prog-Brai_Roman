"""Detecteaza adresele asociate unui posibil atac brute force."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import TypedDict

from arsenal.aparare.parse_auth import citeste_esecuri, pe_ip


class Suspect(TypedDict):
    ip: str
    incercari: int


class Raport(TypedDict):
    esecuri: int
    pe_ip: dict[str, int]
    suspecti: list[Suspect]
    prag: int


def suspecti(counts: Counter[str] | dict[str, int], prag: int = 10) -> list[tuple[str, int]]:
    """Intoarce adresele care ating pragul, sortate descrescator dupa numar."""
    if prag < 1:
        raise ValueError(f"prag invalid: {prag} (cel putin 1)")
    return sorted(
        ((ip, numar) for ip, numar in counts.items() if numar >= prag),
        key=lambda element: (-element[1], element[0]),
    )


def construieste_raport(cale: str | Path, prag: int = 10) -> Raport:
    """Leaga parsarea, numararea si detectia intr-un rezultat reutilizabil."""
    esecuri = citeste_esecuri(cale)
    numaratoare = pe_ip(esecuri)
    lista_suspecti = suspecti(numaratoare, prag)
    return {
        "esecuri": len(esecuri),
        "pe_ip": dict(numaratoare.most_common()),
        "suspecti": [
            {"ip": ip, "incercari": numar} for ip, numar in lista_suspecti
        ],
        "prag": prag,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detecteaza un posibil atac brute force din auth.log."
    )
    parser.add_argument("log", help="calea catre jurnalul auth.log")
    parser.add_argument("--prag", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="afiseaza raport JSON")
    argumente = parser.parse_args(argv)

    try:
        raport = construieste_raport(argumente.log, argumente.prag)
    except ValueError as eroare:
        parser.error(str(eroare))

    if argumente.json:
        print(json.dumps(raport, ensure_ascii=False, indent=2))
        return 0

    print(f"Esecuri de autentificare: {raport['esecuri']}")
    for ip, numar in raport["pe_ip"].items():
        print(f"  {ip}: {numar}")
    print(f"Suspecti (prag {raport['prag']}):")
    if not raport["suspecti"]:
        print("  niciun suspect")
    else:
        for element in raport["suspecti"]:
            print(
                f"  {element['ip']}  ({element['incercari']} incercari)  BRUTE FORCE"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
