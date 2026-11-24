"""Teste pentru enumerarea si compararea capturilor Linux."""

import unittest
from pathlib import Path

from arsenal.privesc.diferenta import analizeaza
from arsenal.privesc.enum import enumereaza, filtreaza_risc


CAPTURI = Path(__file__).with_name("start")


class TestColectii(unittest.TestCase):
    def test_doar_ce_e_nou(self) -> None:
        acum = {"a", "b", "c"}
        baza = {"a", "b"}
        self.assertEqual(acum - baza, {"c"})

    def test_diferenta_reala(self) -> None:
        rezultat = analizeaza(CAPTURI)
        self.assertEqual(
            rezultat["noi"],
            {"/bin/cp", "/usr/bin/find", "/usr/bin/nmap", "/usr/bin/vim.basic"},
        )
        self.assertEqual(
            rezultat["periculoase"],
            ["/bin/cp", "/usr/bin/find", "/usr/bin/nmap", "/usr/bin/vim.basic"],
        )

    def test_numarul_constatarilor(self) -> None:
        raport = enumereaza(CAPTURI)
        self.assertEqual(len(raport["suid"]), 13)
        self.assertEqual(len(raport["sudo"]), 3)
        self.assertEqual(len(raport["cron"]), 3)

    def test_filtrul_de_risc(self) -> None:
        raport = filtreaza_risc(enumereaza(CAPTURI), "mare")
        self.assertEqual(len(raport["suid"]), 4)
        self.assertEqual(len(raport["sudo"]), 2)
        self.assertEqual(raport["cron"], [])


if __name__ == "__main__":
    unittest.main()

