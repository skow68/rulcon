#!/usr/bin/env python3
"""Skrypt do testowania funkcji grupowania reguł względem kryterium - urządzenie-src_zone-dst_zone.
Chodzi o to, aby dostepy z wniosku na grupy, tak aby można było skonfigurować jedno urządzenie za jednym podejściem.
W dodatku uzupełnić surowe reguły z wniosku o parę src zone i dst zone.
Wejściem jest plik udający wyjście procedury wyznaczającej ścieżki (set_path), Wyjściem - struktura reguł gotowa 
do zakodowania w formie charakterystycznej dla firewall'a.
"""
import regool
import pprint
import texttable
from collections import defaultdict

"""
def rule_factory(routetable):
    rule_paths = defaultdict(list)
    for r in routetable:
        rule_paths[str([r[0], r[2], r[4]])].append([r[1], r[3], r[5]])
    # ----presentation
    table = texttable.Texttable()
    table.set_max_width(140)
    for r in rule_paths:
        table.add_row([r, rule_paths[r]])
    print("ROUTEPATHS")
    print(table.draw())
    # ----------------
    ready_for_edge = {}
    for r_path, r in rule_paths.items():
        rulset = regool.rulcon.rule_construct(r)
        list_r_path = eval(r_path)
        rulset = [list_r_path[1:] + x for x in rulset]
        try:
            ready_for_edge[list_r_path[0]].append(rulset)
        except KeyError:
            ready_for_edge[list_r_path[0]] = []
            ready_for_edge[list_r_path[0]].append(rulset)
    # ----presentation
    print("READY FOR EDGE")
    print("Uwaga: Wydruk nie odpowiada w pełni zwracanej strukturze, ale treść jest ok")
    for r in ready_for_edge:
        for rr in ready_for_edge[r]:
            print(r, ":")
            for rrr in rr:
                print("\t", rrr)
    # ----------------
    return ready_for_edge
"""

pp = pprint.PrettyPrinter(indent=4, width=120, depth=6)
routetablefile = open('routetable.txt', 'r')
routetable = eval(routetablefile.read())
# ----presentation
table = texttable.Texttable()
table.set_max_width(0)
for r in routetable:
    table.add_row(r)
print("ROUTETABLE")
print(table.draw())
# ----------------
res = regool.rulcon.rule_factory(routetable)
print(res)

