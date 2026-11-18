"""Execută toate etapele laboratorului și salvează un rezumat JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from arsenal.forensics.decode import decodeaza_straturi, sparge_fisier_hashuri, sparge_xor_un_octet
from arsenal.forensics.forensics import analizeaza
from arsenal.forensics.stego_lsb import ascunde, dezvaluie


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    root = Path(__file__).resolve().parent
    probe = root / "probe"
    mesaj = decodeaza_straturi((probe / "mesaj.txt").read_text(encoding="utf-8"))
    xor = sparge_xor_un_octet((probe / "xor.bin").read_bytes())
    hashuri = sparge_fisier_hashuri(probe / "hashuri.txt", probe / "wordlist.txt")
    fisiere = analizeaza(probe, root)
    stego = root / "stego.png"
    ascunde(probe / "foto.jpg", stego, "FLAG{ascuns_in_pixeli}")
    lsb = dezvaluie(stego)
    rezumat = {"mesaj_straturi": mesaj, "xor": xor, "hashuri": hashuri, "fisiere": fisiere, "mesaj_lsb": lsb}
    (root / "rezultate_lab6.json").write_text(json.dumps(rezumat, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print("Mesaj în straturi:", mesaj["rezultat"])
    print("XOR:", xor["cheie_hex"], xor["rezultat"])
    print("Parole:", ", ".join(r["parola"] or "negăsit" for r in hashuri))
    print("Tipuri:", fisiere["tip_foto"], fisiere["tip_ascuns"])
    print("GPS:", fisiere["exif"].get("GPSDecimal"))
    print("Carving:", fisiere["carving"])
    print("LSB:", lsb)


if __name__ == "__main__":
    main()
