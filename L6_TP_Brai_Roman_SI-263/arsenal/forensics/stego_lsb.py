"""Ascundere și extragere de text în biții LSB ai unei imagini PNG."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import cast

from PIL import Image


def _pixeli_rgb(img: Image.Image) -> list[tuple[int, int, int]]:
    """Returnează pixelii RGB într-o formă cunoscută de analizorul de tipuri."""
    date = cast(Iterable[tuple[int, int, int]], img.getdata())
    return list(date)


def ascunde(imagine: str | Path, iesire: str | Path, mesaj: str) -> None:
    img = Image.open(imagine).convert("RGB")
    pixeli = _pixeli_rgb(img)
    date = mesaj.encode("utf-8") + b"\x00"
    biti = "".join(f"{byte:08b}" for byte in date)
    if len(biti) > len(pixeli) * 3:
        raise ValueError("Mesajul nu încape în imagine")
    canale = [canal for pixel in pixeli for canal in pixel]
    for index, bit in enumerate(biti):
        canale[index] = (canale[index] & ~1) | int(bit)
    pixeli_noi = [tuple(canale[i : i + 3]) for i in range(0, len(canale), 3)]
    img.putdata(pixeli_noi)
    img.save(iesire, format="PNG")


def dezvaluie(imagine: str | Path) -> str:
    img = Image.open(imagine).convert("RGB")
    pixeli = _pixeli_rgb(img)
    biti = "".join(str(canal & 1) for pixel in pixeli for canal in pixel)
    rezultat = bytearray()
    for index in range(0, len(biti) - 7, 8):
        byte = int(biti[index : index + 8], 2)
        if byte == 0:
            break
        rezultat.append(byte)
    return rezultat.decode("utf-8")


def main() -> None:
    reconfigure_stdout = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure_stdout):
        reconfigure_stdout(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Steganografie LSB")
    parser.add_argument("comanda", choices=("ascunde", "dezvaluie"))
    parser.add_argument("imagine")
    parser.add_argument("--iesire", default="stego.png")
    parser.add_argument("--mesaj", default="FLAG{ascuns_in_pixeli}")
    args = parser.parse_args()
    if args.comanda == "ascunde":
        ascunde(args.imagine, args.iesire, args.mesaj)
        print(f"Mesaj ascuns în {args.iesire}")
    else:
        print(dezvaluie(args.imagine))


if __name__ == "__main__":
    main()
