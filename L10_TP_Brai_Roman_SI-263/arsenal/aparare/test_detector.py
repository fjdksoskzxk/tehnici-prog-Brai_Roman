"""Teste pentru parsarea jurnalului si detectorul brute force."""

import tempfile
import unittest
from collections import Counter
from pathlib import Path

from arsenal.aparare.detector import construieste_raport, suspecti
from arsenal.aparare.parse_auth import esec, pe_ip


class TestDetector(unittest.TestCase):
    def test_esec_accepta_utilizator_valid_si_invalid(self) -> None:
        self.assertEqual(
            esec("Failed password for root from 203.0.113.9 port 51230 ssh2"),
            ("root", "203.0.113.9"),
        )
        self.assertEqual(
            esec(
                "Failed password for invalid user admin "
                "from 203.0.113.9 port 51240 ssh2"
            ),
            ("admin", "203.0.113.9"),
        )
        self.assertIsNone(esec("<linie stricata fara structura>"))

    def test_numararea_pe_ip(self) -> None:
        date = [
            {"user": "root", "ip": "a"},
            {"user": "admin", "ip": "a"},
            {"user": "ana", "ip": "b"},
        ]
        self.assertEqual(pe_ip(date), Counter({"a": 2, "b": 1}))

    def test_pragul_taie(self) -> None:
        counts = Counter({"a": 13, "b": 2})
        self.assertEqual(suspecti(counts, 10), [("a", 13)])
        self.assertEqual(suspecti(counts, 2), [("a", 13), ("b", 2)])

    def test_prag_invalid(self) -> None:
        with self.assertRaisesRegex(ValueError, "prag invalid: 0"):
            suspecti({}, 0)

    def test_raportul_real(self) -> None:
        with tempfile.TemporaryDirectory() as director:
            jurnal = Path(director) / "auth.log"
            jurnal.write_text(
                "Failed password for root from 203.0.113.9 port 1 ssh2\n"
                "<linie stricata>\n"
                "Failed password for invalid user admin "
                "from 203.0.113.9 port 2 ssh2\n",
                encoding="utf-8",
            )
            raport = construieste_raport(jurnal, prag=2)
        self.assertEqual(raport["esecuri"], 2)
        self.assertEqual(raport["pe_ip"], {"203.0.113.9": 2})
        self.assertEqual(
            raport["suspecti"], [{"ip": "203.0.113.9", "incercari": 2}]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
