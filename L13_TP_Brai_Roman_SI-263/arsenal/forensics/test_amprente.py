"""Teste pytest pentru unealta de amprentare."""

import os

from arsenal.forensics.amprente import (
    amprenta_fisier,
    amprente_lenes,
    scaneaza,
    tip,
)


PROBE = os.path.join(os.path.dirname(__file__), "probe")


def test_tip_din_magic():
    assert tip(b"\x89PNG") == "PNG"
    assert tip(b"%PDF-1.4") == "PDF"
    assert tip(b"PK\x03\x04") == "ZIP"
    assert tip(b"text") == "necunoscut"


def test_amprenta_png():
    rezultat = amprenta_fisier(os.path.join(PROBE, "imagine.png"))
    assert rezultat["tip"] == "PNG"
    assert rezultat["sha256"] == "ea3a9848da7e6c1d"


def test_scaneaza_toate():
    rezultate = scaneaza(PROBE)
    assert len(rezultate) == 4
    assert [fisa["nume"] for fisa in rezultate] == [
        "arhiva.zip",
        "imagine.png",
        "note.txt",
        "raport.pdf",
    ]
    assert {fisa["tip"] for fisa in rezultate} == {
        "PNG",
        "PDF",
        "ZIP",
        "necunoscut",
    }
    assert list(amprente_lenes(PROBE)) == rezultate
