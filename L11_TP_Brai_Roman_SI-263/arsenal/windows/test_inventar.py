"""Teste pentru obiectele si inventarul Windows."""

import json
import tempfile
import unittest
from pathlib import Path

from arsenal.windows.inventar import (
    Eveniment,
    Inventar,
    Proces,
    construieste_raport,
)


class TestInventar(unittest.TestCase):
    def test_proces_din_temp_e_suspect(self) -> None:
        proces = Proces(1, "x.exe", "ana", r"C:\Users\ana\AppData\Local\Temp\x.exe")
        self.assertTrue(proces.e_suspect())

    def test_proces_din_windows_nu_e_suspect(self) -> None:
        proces = Proces(2, "svchost.exe", "SYSTEM", r"C:\Windows\System32\svchost.exe")
        self.assertFalse(proces.e_suspect())

    def test_eveniment_suspect_dupa_id_sau_nivel(self) -> None:
        self.assertTrue(Eveniment(4625, "warning", "Security", "ana", "x").e_suspect())
        self.assertTrue(Eveniment(9999, "critical", "App", "ana", "x").e_suspect())
        self.assertFalse(Eveniment(4624, "info", "Security", "ana", "x").e_suspect())

    def test_inventar_suspecte_si_grupare(self) -> None:
        inventar = Inventar(
            [
                Proces(1, "System", "SYSTEM", r"C:\Windows\System32\a.exe"),
                Proces(2, "x.exe", "ana", r"C:\Users\ana\AppData\Roaming\x.exe"),
                Proces(3, "explorer.exe", "ana", r"C:\Windows\explorer.exe"),
            ]
        )
        self.assertEqual(inventar.suspecte(), [inventar.procese[1]])
        self.assertEqual(
            inventar.pe_user(),
            {"SYSTEM": ["System"], "ana": ["x.exe", "explorer.exe"]},
        )

    def test_incarcare_si_raport(self) -> None:
        with tempfile.TemporaryDirectory() as director:
            baza = Path(director)
            (baza / "procese.json").write_text(
                json.dumps(
                    [
                        {"pid": 1, "nume": "x.exe", "user": "ana", "cale": r"C:\Users\ana\AppData\Local\Temp\x.exe"},
                        {"pid": 2, "nume": "ok.exe", "user": "SYSTEM", "cale": r"C:\Windows\ok.exe"},
                    ]
                ),
                encoding="utf-8",
            )
            (baza / "evenimente.json").write_text(
                json.dumps(
                    [
                        {"id": 1102, "nivel": "critical", "sursa": "Security", "cont": "admin", "mesaj": "cleared"},
                        {"id": 4624, "nivel": "info", "sursa": "Security", "cont": "ana", "mesaj": "ok"},
                    ]
                ),
                encoding="utf-8",
            )
            raport = construieste_raport(baza)
        self.assertEqual(raport["procese"], 2)
        self.assertEqual(len(raport["procese_suspecte"]), 1)
        self.assertEqual(raport["evenimente"], 2)
        self.assertEqual(len(raport["alarme"]), 1)
        self.assertEqual(raport["scor_risc"], 2)

    def test_json_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as director:
            cale = Path(director) / "procese.json"
            cale.write_text("{invalid", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON invalid"):
                Inventar.din_json(cale)


if __name__ == "__main__":
    unittest.main(verbosity=2)
