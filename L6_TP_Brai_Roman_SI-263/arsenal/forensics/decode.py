"""Decoder universal pentru laboratorul de forensics."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote_to_bytes

FISA_PATH = Path(__file__).with_name("fisa.json")


def ghici_strat(s: str) -> str:
    """Clasifică un șir ca URL, hex, base64 sau necunoscut."""
    value = s.strip()
    if re.search(r"%[0-9A-Fa-f]{2}", value):
        return "url"
    if value and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", value):
        return "hex"
    if value and len(value) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        try:
            base64.b64decode(value, validate=True)
            return "base64"
        except binascii.Error:
            pass
    return "necunoscut"


def desfa(s: str) -> tuple[str, bytes]:
    """Desface un singur strat și întoarce tipul și octeții rezultați."""
    value = s.strip()
    strat = ghici_strat(value)
    if strat == "url":
        return strat, unquote_to_bytes(value)
    if strat == "hex":
        return strat, bytes.fromhex(value)
    if strat == "base64":
        return strat, base64.b64decode(value, validate=True)
    return strat, value.encode("utf-8")


def citibil(data: bytes) -> bool:
    """Verifică dacă octeții sunt ASCII imprimabili sau spații uzuale."""
    return bool(data) and all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data)


def decodeaza_straturi(value: str, limita: int = 8) -> dict[str, object]:
    """Desface repetat straturile detectabile până la textul clar."""
    curent = value.strip()
    pasi: list[str] = []
    rezultat = curent.encode("utf-8")
    for _ in range(limita):
        strat = ghici_strat(curent)
        if strat == "necunoscut":
            break
        strat, rezultat = desfa(curent)
        pasi.append(strat)
        if not citibil(rezultat):
            break
        curent = rezultat.decode("ascii")
    text = rezultat.decode("utf-8", errors="replace")
    return {"straturi": pasi, "rezultat": text}


def xor_cu_cheie(data: bytes, cheie: int) -> bytes:
    return bytes(byte ^ cheie for byte in data)


def sparge_xor_un_octet(data: bytes) -> dict[str, object]:
    """Încearcă toate cheile și alege candidatul imprimabil cu scor maxim."""
    candidati = []
    for cheie in range(256):
        clar = xor_cu_cheie(data, cheie)
        if citibil(clar):
            text = clar.decode("ascii")
            scor = 100 if "FLAG{" in text else 0
            scor += sum(token in text.lower() for token in ("secret", "octet", "cheie")) * 10
            scor += sum(ch.isalpha() or ch.isspace() for ch in text) / max(1, len(text))
            candidati.append((scor, cheie, text))
    if not candidati:
        raise ValueError("Nu a fost găsit niciun rezultat imprimabil")
    _, cheie, text = max(candidati)
    return {"cheie": cheie, "cheie_hex": f"0x{cheie:02x}", "rezultat": text}


def algoritm_hash(hash_hex: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(hash_hex.strip()), "necunoscut")


def sparge_hash(hash_hex: str, cuvinte: list[str]) -> dict[str, object]:
    """Caută în dicționar preimaginea unui MD5, SHA1 sau SHA256."""
    tinta = hash_hex.strip().lower()
    algoritm = algoritm_hash(tinta)
    if algoritm == "necunoscut":
        return {"hash": tinta, "algoritm": algoritm, "parola": None}
    for cuvant in cuvinte:
        digest = hashlib.new(algoritm, cuvant.encode("utf-8")).hexdigest()
        if digest == tinta:
            return {"hash": tinta, "algoritm": algoritm, "parola": cuvant}
    return {"hash": tinta, "algoritm": algoritm, "parola": None}


def sparge_fisier_hashuri(hashuri: Path, wordlist: Path) -> list[dict[str, object]]:
    cuvinte = [line.strip() for line in wordlist.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [sparge_hash(line, cuvinte) for line in hashuri.read_text(encoding="utf-8").splitlines() if line.strip()]


def proceseaza(
    intrare: str, este_fisier: bool, wordlist: str | None = None
) -> dict[str, object]:
    if not este_fisier:
        rezultat = decodeaza_straturi(intrare)
        return {"tip": "sir", **rezultat}

    cale = Path(intrare)
    date = cale.read_bytes()
    if wordlist and algoritm_hash(date.decode("ascii", errors="ignore").strip()) != "necunoscut":
        cuvinte = Path(wordlist).read_text(encoding="utf-8").splitlines()
        return {"tip": "hash", **sparge_hash(date.decode().strip(), cuvinte)}

    try:
        text = date.decode("ascii").strip()
    except UnicodeDecodeError:
        return {"tip": "xor", **sparge_xor_un_octet(date)}
    if ghici_strat(text) != "necunoscut":
        return {"tip": "fisier_codat", **decodeaza_straturi(text)}
    return {"tip": "text", "rezultat": text}


def main() -> None:
    reconfigure_stdout = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure_stdout):
        reconfigure_stdout(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Decoder universal pentru laborator")
    parser.add_argument("intrare", help="Șirul de decodat sau calea fișierului")
    parser.add_argument("--fisier", action="store_true", help="Tratează intrarea ca fișier")
    parser.add_argument("--wordlist", help="Dicționar pentru un hash furnizat ca fișier")
    args = parser.parse_args()
    rezultat = proceseaza(args.intrare, args.fisier, args.wordlist)
    FISA_PATH.write_text(json.dumps(rezultat, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(rezultat, ensure_ascii=False, indent=2))
    print(f"Fișa a fost salvată în {FISA_PATH}")


if __name__ == "__main__":
    main()
