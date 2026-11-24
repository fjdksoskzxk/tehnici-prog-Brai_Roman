"""Modeleaza procesele si evenimentele Windows ca obiecte Python."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, TypedDict


CAI_SUSPECTE = ("\\Temp\\", "\\Roaming\\")
SUSPECTE_ID = {4625, 1102, 7045}


class Raport(TypedDict):
    procese: int
    procese_suspecte: list[dict[str, Any]]
    pe_user: dict[str, list[str]]
    evenimente: int
    alarme: list[dict[str, Any]]
    scor_risc: int


@dataclass(frozen=True, slots=True)
class Proces:
    pid: int
    nume: str
    user: str
    cale: str

    def e_suspect(self) -> bool:
        """Intoarce True daca procesul ruleaza dintr-o cale de utilizator riscanta."""
        cale_normalizata = self.cale.casefold()
        return any(fragment.casefold() in cale_normalizata for fragment in CAI_SUSPECTE)


@dataclass(frozen=True, slots=True)
class Eveniment:
    id: int
    nivel: str
    sursa: str
    cont: str
    mesaj: str

    def e_suspect(self) -> bool:
        """Intoarce True pentru ID-uri cunoscute sau nivelul critical."""
        return self.id in SUSPECTE_ID or self.nivel.casefold() == "critical"

    def explica(self) -> str:
        explicatii = {
            4625: "autentificare esuata",
            1102: "jurnal de audit sters",
            7045: "serviciu nou instalat",
        }
        return explicatii.get(self.id, "eveniment analizat dupa nivel")


def _citeste_lista_json(cale: str | Path) -> list[dict[str, Any]]:
    """Citeste o lista JSON si ofera erori explicite pentru input invalid."""
    try:
        with open(cale, encoding="utf-8") as fisier:
            date = json.load(fisier)
    except FileNotFoundError as eroare:
        raise FileNotFoundError(f"nu gasesc fisierul: {cale}") from eroare
    except json.JSONDecodeError as eroare:
        raise ValueError(f"JSON invalid in {cale}: {eroare.msg}") from eroare

    if not isinstance(date, list):
        raise ValueError(f"se asteapta o lista JSON in {cale}")
    return date


def procese_din_json(cale: str | Path) -> list[Proces]:
    return [Proces(**element) for element in _citeste_lista_json(cale)]


def evenimente_din_json(cale: str | Path) -> list[Eveniment]:
    return [Eveniment(**element) for element in _citeste_lista_json(cale)]


@dataclass
class Inventar:
    procese: list[Proces]

    @classmethod
    def din_json(cls, cale: str | Path) -> "Inventar":
        return cls(procese_din_json(cale))

    def __len__(self) -> int:
        return len(self.procese)

    def suspecte(self) -> list[Proces]:
        return [proces for proces in self.procese if proces.e_suspect()]

    def pe_user(self) -> dict[str, list[str]]:
        rezultat: dict[str, list[str]] = {}
        for proces in self.procese:
            rezultat.setdefault(proces.user, []).append(proces.nume)
        return rezultat


def construieste_raport(capturi: str | Path) -> Raport:
    baza = Path(capturi)
    inventar = Inventar.din_json(baza / "procese.json")
    evenimente = evenimente_din_json(baza / "evenimente.json")
    procese_suspecte = inventar.suspecte()
    alarme = [eveniment for eveniment in evenimente if eveniment.e_suspect()]
    return {
        "procese": len(inventar),
        "procese_suspecte": [asdict(proces) for proces in procese_suspecte],
        "pe_user": inventar.pe_user(),
        "evenimente": len(evenimente),
        "alarme": [asdict(eveniment) | {"explicatie": eveniment.explica()} for eveniment in alarme],
        "scor_risc": len(procese_suspecte) + len(alarme),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inventar de procese si evenimente Windows."
    )
    parser.add_argument("capturi", help="folderul cu procese.json si evenimente.json")
    parser.add_argument("--json", action="store_true", help="afiseaza raportul JSON")
    argumente = parser.parse_args(argv)

    try:
        raport = construieste_raport(argumente.capturi)
    except (FileNotFoundError, ValueError, TypeError) as eroare:
        parser.error(str(eroare))

    if argumente.json:
        print(json.dumps(raport, ensure_ascii=False, indent=2))
        return 0

    suspecte = raport["procese_suspecte"]
    alarme = raport["alarme"]
    print(f"Procese: {raport['procese']} | suspecte: {len(suspecte)}")
    for proces in suspecte:
        print(
            f"  [{proces['pid']}] {proces['nume']}  "
            f"({proces['user']})  {proces['cale']}"
        )
    print(f"Evenimente: {raport['evenimente']} | alarma: {len(alarme)}")
    for eveniment in alarme:
        print(
            f"  {eveniment['id']} [{eveniment['nivel']}] "
            f"{eveniment['cont']}: {eveniment['mesaj']}"
        )
    print(f"Scor de risc: {raport['scor_risc']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
