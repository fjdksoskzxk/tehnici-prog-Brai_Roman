"""Unealta reparată pentru Lucrarea B."""

import hashlib
import os


MAGIC = {b"\x89PNG": "PNG", b"%PDF": "PDF", b"PK\x03\x04": "ZIP"}


def tip(head):
    for semnatura, nume in MAGIC.items():
        if head.startswith(semnatura):
            return nume
    return "necunoscut"


def amprenta_fisier(cale):
    with open(cale, "rb") as fisier:
        date = fisier.read()
    return {
        "nume": os.path.basename(cale),
        "tip": tip(date[:8]),
        "sha256": hashlib.sha256(date).hexdigest()[:16],
    }


def scaneaza(folder):
    rezultate = []
    for nume in sorted(os.listdir(folder)):
        cale = os.path.join(folder, nume)
        if os.path.isfile(cale):
            rezultate.append(amprenta_fisier(cale))
    return rezultate
