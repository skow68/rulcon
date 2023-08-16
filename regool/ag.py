#!/usr/bin/env python3
from rulcon import rule_construct
import openpyxl
import texttable
apps = {
    'nfs': ['nfs', 'mount', 'portmaper'],
    'samba': ['ms-ds-smb']
}
workbook = openpyxl.load_workbook("local.xlsx")
worksheet = workbook['Arkusz1']
my_dns = {}
for row in worksheet.iter_rows(values_only=True, min_row=3):
    my_dns[row[1]] = row[0]
    my_dns[row[2]] = row[3]
opti_rules = rule_construct(worksheet)
tableform2 = texttable.Texttable()
for lst in opti_rules:
    tableform2.add_row([lst[0], lst[1], lst[2], lst[3]])
print("Final table:")
print(tableform2.draw())
