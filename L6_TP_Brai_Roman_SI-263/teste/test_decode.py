from pathlib import Path
import unittest

from arsenal.forensics.decode import (
    decodeaza_straturi,
    desfa,
    sparge_fisier_hashuri,
    sparge_xor_un_octet,
)


ROOT = Path(__file__).resolve().parents[1]


class TestDecode(unittest.TestCase):
    def test_base64(self):
        strat, rezultat = desfa("U2FsdXQ=")
        self.assertEqual(strat, "base64")
        self.assertEqual(rezultat, b"Salut")

    def test_mesaj_cu_straturi(self):
        valoare = (ROOT / "probe" / "mesaj.txt").read_text(encoding="utf-8")
        rezultat = decodeaza_straturi(valoare)
        self.assertEqual(rezultat["straturi"], ["base64", "base64", "hex"])
        self.assertEqual(rezultat["rezultat"], "FLAG{straturi_de_encoding}")

    def test_xor(self):
        rezultat = sparge_xor_un_octet((ROOT / "probe" / "xor.bin").read_bytes())
        self.assertEqual(rezultat["cheie"], 0x80)
        self.assertIn("FLAG{xor_un_octet}", rezultat["rezultat"])

    def test_hashuri(self):
        rezultate = sparge_fisier_hashuri(ROOT / "probe" / "hashuri.txt", ROOT / "probe" / "wordlist.txt")
        self.assertEqual(
            [r["parola"] for r in rezultate],
            ["password", "dragon", "qwerty", "letmein", "monkey"],
        )


if __name__ == "__main__":
    unittest.main()
