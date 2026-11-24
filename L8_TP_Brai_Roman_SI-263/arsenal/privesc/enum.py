"""Grupeaza capturile SUID, sudo si cron intr-un raport JSON."""

from __future__ import annotations

import os
import sys

# La rularea directa, directorul care contine enum.py ajunge primul in sys.path
# si poate masca modulul standard "enum". Il eliminam inainte de alte importuri.
if __package__ in (None, ""):
    director_script = os.path.dirname(os.path.abspath(__file__))
    sys.path = [cale for cale in sys.path if os.path.abspath(cale) != director_script]
    sys.path.insert(0, os.path.dirname(os.path.dirname(director_script)))

import argparse
import json
from pathlib import Path
from typing import Any


GTFO = {
    "find",
    "vim.basic",
    "vim",
    "nmap",
    "cp",
    "bash",
    "less",
    "awk",
    "python3",
    "perl",
}


def citeste_linii(cale: str | Path) -> list[str]:
    """Intoarce liniile utile, fara goluri si comentarii."""
    with Path(cale).open(encoding="utf-8") as fisier:
        return [
            linie_curata
            for linie in fisier
            if (linie_curata := linie.strip()) and not linie_curata.startswith("#")
        ]


def nume(cale: str) -> str:
    """Extrage numele fisierului dintr-o cale Linux."""
    return cale.rsplit("/", 1)[-1]


def suid_constatari(cale: str | Path) -> list[dict[str, str]]:
    """Construieste constatari SUID unice si sortate."""
    return [
        {
            "cale": item,
            "nume": nume(item),
            "risc": "mare" if nume(item) in GTFO else "normal",
        }
        for item in sorted(set(citeste_linii(cale)))
    ]


def sudo_constatari(cale: str | Path) -> list[dict[str, str]]:
    """Interpreteaza liniile user : drept din captura sudo."""
    rezultate: list[dict[str, str]] = []
    for linie in citeste_linii(cale):
        user, drept = linie.split(" : ", 1)
        drept = drept.strip()
        rezultate.append(
            {
                "user": user.strip(),
                "drept": drept,
                "risc": "mare" if "NOPASSWD" in drept else "normal",
            }
        )
    return rezultate


def cron_constatari(cale: str | Path) -> list[dict[str, str]]:
    """Extrage utilizatorul si comanda din fiecare intrare crontab."""
    rezultate: list[dict[str, str]] = []
    for linie in citeste_linii(cale):
        campuri = linie.split()
        if len(campuri) < 7:
            raise ValueError(f"Linie cron invalida: {linie}")
        rezultate.append(
            {
                "user": campuri[5],
                "comanda": " ".join(campuri[6:]),
                "risc": "normal",
            }
        )
    return rezultate


def enumereaza(director: str | Path) -> dict[str, list[dict[str, str]]]:
    """Grupeaza toate constatarile pe categorii."""
    baza = Path(director)
    return {
        "suid": suid_constatari(baza / "suid.txt"),
        "sudo": sudo_constatari(baza / "sudo.txt"),
        "cron": cron_constatari(baza / "crontab.txt"),
    }


def filtreaza_risc(
    raport: dict[str, list[dict[str, str]]], risc: str | None
) -> dict[str, list[dict[str, str]]]:
    """Filtreaza optional toate categoriile dupa nivelul de risc."""
    if risc is None:
        return raport
    return {
        categorie: [item for item in constatari if item.get("risc") == risc]
        for categorie, constatari in raport.items()
    }


def grupeaza_dupa_risc(
    raport: dict[str, list[dict[str, str]]]
) -> dict[str, list[str]]:
    """Grupeaza denumirile constatarilor dupa risc folosind setdefault."""
    grupuri: dict[str, list[str]] = {}
    for constatari in raport.values():
        for item in constatari:
            eticheta = item.get("nume") or item.get("user") or item.get("comanda", "necunoscut")
            grupuri.setdefault(item.get("risc", "necunoscut"), []).append(eticheta)
    return {risc: sorted(valori) for risc, valori in grupuri.items()}


def utilizatori_implicati(raport: dict[str, list[dict[str, str]]]) -> set[str]:
    """Reuneste utilizatorii din sudo si cron."""
    sudo_users = {item["user"] for item in raport["sudo"]}
    cron_users = {item["user"] for item in raport["cron"]}
    return sudo_users | cron_users


def main() -> None:
    parser = argparse.ArgumentParser(description="Enumerare defensiva din capturi Linux")
    parser.add_argument(
        "capturi",
        nargs="?",
        type=Path,
        default=Path(__file__).with_name("start"),
        help="folderul cu suid.txt, sudo.txt si crontab.txt",
    )
    parser.add_argument("--json", action="store_true", help="afiseaza raportul ca JSON")
    parser.add_argument("--risc", choices=("mare", "normal"), help="filtreaza dupa risc")
    parser.add_argument(
        "--grupare-risc", action="store_true", help="afiseaza si gruparea numelor dupa risc"
    )
    argumente = parser.parse_args()

    raport_complet = enumereaza(argumente.capturi)
    raport = filtreaza_risc(raport_complet, argumente.risc)

    if argumente.json:
        print(json.dumps(raport, indent=2, ensure_ascii=False))
        return

    for categorie, constatari in raport.items():
        mari = [item for item in constatari if item.get("risc") == "mare"]
        print(f"{categorie}: {len(constatari)} gasite, {len(mari)} cu risc mare")

    utilizatori = ", ".join(sorted(utilizatori_implicati(raport_complet)))
    print(f"utilizatori implicati: {utilizatori}")

    if argumente.grupare_risc:
        print("grupare dupa risc:")
        print(json.dumps(grupeaza_dupa_risc(raport_complet), indent=2, ensure_ascii=False))

    iesire = Path(__file__).with_name("enum.json")
    with iesire.open("w", encoding="utf-8") as fisier:
        json.dump(raport, fisier, indent=2, ensure_ascii=False)
    print(f"Raport salvat in {iesire.as_posix()}")


if __name__ == "__main__":
    main()

