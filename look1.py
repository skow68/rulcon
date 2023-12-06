#!/usr/bin/env python3
# Skrypt do testowania zapobiegania tworzenia zdublowanych AG na Palo
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressObject, AddressGroup
fw = Firewall("192.168.39.9", api_username="", api_password="xxxxxxxxx", vsys="vsys2")
# Z wniosku dostajemy listę IP i ich nazwy (src lub dst). Sprawdzamy po kolei, czy obiekty AO o odpowiedniej
# nazwie istnieją. Jeśli nie to tworzymy.
# Jeśli tak, to sprawdzamy, czy jest AG, która zawiera adresy z listy (dokładnie te adresy).
AddressObject.refreshall(fw, add=True)
# tutaj komponujemy nazwę AO według przyjetego standardu i w pętli szukamy
# ao = fw.find('vnet-prod-nit-172.18.5.0-24', AddressObject)
# print(ao.value)
iplist = ["vnet-prod-nit-172.18.5.0-24", "VNet-PROD-PAdP-App-172.18.6.0-26", "VNet-PROD-PAdP-DB-172.18.6.64-26"]
# jeśli nie istnieje to tworzymy; jeśli nie istnieje chociaż jeden to już nie przeszukujemy AG
# jeśi wszystkie istniały, to szukamy pierwszego z brzegu w AG
AddressGroup.refreshall(fw, add=True)
groups = fw.findall(AddressGroup)
bingo = 0
for group in groups:
    if set(group.static_value) == set(iplist):
        bingo = group.uid
        break
print(bingo)
#test git 1
