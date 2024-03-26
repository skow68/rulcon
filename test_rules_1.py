import csv
import regool.rulcon
from rich import inspect
"""Test rulcon.rule_factory"""
file_name = 'csv/local3.csv'
with open(file_name, "r") as file:
    reader = csv.reader(file, delimiter=";")
    input_rules = [row for row in reader]
#print(input_rules)
fullinfo_table = []
my_dns = {}
for row in input_rules:
    my_dns[row[2]] = row[1]
    my_dns[row[5]] = row[4]
    dev = row[0]
    src = row[2]
    src_zone = row[3]
    dst = row[5]
    dst_zone = row[6]
    port = row[7]
    fullinfo_table.append([dev, src, src_zone, dst, dst_zone, port])
    #fullinfo_table - symulacja tego co nam daje regool.paths.Connections.rules_fullinfo
print('Input:')
print(fullinfo_table)
readytable = regool.rulcon.rule_factory(fullinfo_table)
print('Output:')
inspect(readytable)
