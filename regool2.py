#!/usr/bin/env python3
"""Program główny
local.xlsx - służy do ogólnego testwania funkcji rule_construct, zawiera nieprawdziwe adresy ip
local2.xlsx - służy do testowania paths.show_path
"""
import getpass
import warnings
import openpyxl
import dill as pickle
# import regool.devices
# import regool.rgerrors
import regool
# warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
warnings.filterwarnings('ignore', '.*deprecated.*')


def save_object(obj, filename):
    """Funkcja zachowująca w pliku dowolny obiekt."""
    with open(filename, 'wb') as outp:  # Overwrites any existing file.
        # pickle.dump(obj, outp, pickle.HIGHEST_PROTOCOL)
        pickle.dump(obj, outp)


user = getpass.getuser()
print(user)
# user = ""
# password = getpass.getpass()
password = ''
workbook = openpyxl.load_workbook("local3.xlsx")
worksheet = workbook['Arkusz1']
max_og = 2
max_port = 2
my_dns = {}
basetable = []
for row in worksheet.iter_rows(values_only=True, min_row=3):
    my_dns[row[1]] = row[0]
    my_dns[row[2]] = row[3]
    dst = row[3]
    src = row[1]
    port = row[4]
    basetable.append([src, dst, port])
# rules_fullinfo ma format listy list: [['pfe', '172.18.15.129', 'DMZE-OUTSIDE', '192.168.170.71', 'DMZE-INSIDE', 80]]
# Podczas testów zamiast ściągać dane z urządzeń pobieramy je z obiektu wcześniej zachowanego w pliku.
#with open('connections.pkl', 'rb') as inp:
#    connections = pickle.load(inp)
# nie przechwytujemy wyjątków z Connections, bo i tak powinny zakończyć działanie programu
connections = regool.paths.Connections(basetable, user, password)
# Dzięki poniższej funkcji nie musimy za każdym testem wykonywać połączeń do urządzeń.
# save_object(connections, 'connections.pkl')
readytable = regool.rulcon.rule_factory(connections.rules_fullinfo)
# print(readytable)
reqid = "535353"
for connection in connections.connections_to_fw: #lista obiektów Palo
    print("EDEV:", connection.edev)
    for rule in readytable[connection.edev]:
        print("rule:", rule)
        if len(rule[2]) > max_og:
            rule[2] = connection.compress2ag(rule[2], reqid)
        if len(rule[3]) > max_og:
            rule[3] = connection.compress2ag(rule[3], reqid)
        if len(rule[4]) > max_port:
            rule[4] = connection.compress2sg(rule[4], reqid)
        if len(rule[5]) > max_port:
            rule[5] = connection.compress2sg(rule[5], reqid)

