#!/usr/bin/env python3
from regool.rulcon import rule_construct
import openpyxl
import unittest
# Test nie działa, ponieważ w zwracanej tablicy jest inna kolejność za kadym razem 

class Test_construct(unittest.TestCase):
    def test_me(self):
        self.maxDiff = None
        self.expected = [["['1.1.1.1', '1.1.1.2']", ['2.2.2.2'], ['80', '443'], ''],
                    ["['1.1.1.1', '1.1.1.2', '100.1.1.1', '100.1.1.2', '100.1.1.3']", ['2.2.2.2'], ['22'], ''],
                    ["['1.1.1.3']", ['2.2.2.2'], ['443'], ''], ["['1.1.1.3']", ['2.2.2.2'], '', ['samba', 'nfs']],
                    ["['3.3.3.3', '1.2.3.4']", ['2.2.2.2', '4.4.4.6', '4.4.4.5', '4.4.4.4'],
                     ['32', '80', '33', '31'], ''], ["['7.7.7.7']", ['4.4.4.6', '4.4.4.5', '4.4.4.4'], ['80'], ''],
                    ["['7.7.7.7']", ['2.2.2.2'], '', ['nfs']]]
        workbook = openpyxl.load_workbook("test_rulcon.xlsx")
        worksheet = workbook['Arkusz1']
        self.result = rule_construct(worksheet)
        self.assertListEqual(self.result, self.expected)


if __name__ == "__main__":
    unittest.main()
