"""Rezolvă provocarea opțională base64 peste XOR."""

import base64
import hashlib
import sys
from pathlib import Path

RADACINA = Path(__file__).resolve().parents[2]
if str(RADACINA) not in sys.path:
    sys.path.insert(0, str(RADACINA))

from arsenal.forensics.decode import sparge_xor_un_octet


def main() -> None:
    date = base64.b64decode((RADACINA / "probe" / "challenge.bin").read_bytes())
    rezultat = sparge_xor_un_octet(date)
    text = rezultat["rezultat"]
    print("cheie:", rezultat["cheie_hex"])
    print("text:", text)
    print("md5:", hashlib.md5(text.encode()).hexdigest())


if __name__ == "__main__":
    main()
