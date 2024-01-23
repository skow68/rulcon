#!/usr/bin/env python3
# import sys
import re
import warnings
import regool.rgerrors
from netmiko import ConnectHandler
from netmiko.cisco import CiscoNxosSSH  # tylko dla funkcji isinstance
from panos.errors import PanCommitNotNeeded, PanDeviceError, PanObjectMissing, PanURLError, PanApiKeyNotSet
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressObject, AddressGroup
import yaml
with open('config.yml') as confile:
    try:
        config = yaml.safe_load(confile)
    except yaml.YAMLError as exc:
        print(exc)
# warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
warnings.filterwarnings('ignore', '.*deprecated.*')
route_core = {
    '192.168.245.138': 'fwi',
    '192.168.245.142': 'fwi',
    '192.168.245.166': 'fwe',
    '192.168.245.170': 'fwe',
    '192.168.246.138': 'fwi',
    '192.168.246.142': 'fwi',
    '192.168.246.166': 'fwe',
    '192.168.246.170': 'fwe',
    '192.168.245.146': 'fwc',
    '192.168.246.146': 'fwc',
    '192.168.245.150': 'fwc',
    '192.168.246.150': 'fwc',
    '192.168.245.114': 'swift',
    '192.168.246.114': 'swift',
    '192.168.245.118': 'swift',
    '192.168.246.118': 'swift'
}
devinfo = {
    'fwi': ['Palo', 'fwi-b01', 'VR-I'],
    'fwe': ['Palo', 'fwi-b01', 'VR-E'],
    'fwc': ['Palo', 'fwc-b01', 'VR-VSYS1-VRF'],
    'swift': ['Palo', 'fwc-b01', 'VR-VSYS2-SWIFT']
}
sec_max_ao = 2


# W odróżnieniu od urządzeń brzegowych zakładamy, że jest tylko jeden typ urządzeń core
class Coredev():
    """Kanał komunikacyjny do routerów corowych
    """
    def __init__(self, user, password):
        #self.core = ["core-p01", "core-p02", "core-a01", "core-a01"]
        self.rcoredata = {
            #"device_type": "cisco_Nxos_ssh",
            "username": user,
            "password": password,
            "session_log": "net-core.log",
        }
        self.msg = {
            'NetmikoAuthenticationException': 'Authentication error',
            'NetmikoTimeoutException': 'Timeout error',
        }
        self.error = ''
        for i in self.core:
            self.r = i

    def find_edge(self, ip):
        """Na podstawie routing wyznacza firewall'e, na których należy wykonać konfigurację
        Wydruki błędów należy zamienić logowaniem.
        Sygnalizpwanie błędów należy zamienić na try expect
        """
        self.error = ''
        command = f'show ip route {ip}'
        m = []
        for r in config['core']:
            self.rcoredata['host'] = r
            self.rcoredata['device_type'] = config['core'][r]['type']
            if not isinstance(self.r, CiscoNxosSSH):
                # print("Creating new netmiko object")
                try:
                    self.r = ConnectHandler(**self.rcoredata)
                    # print(r.__dict__)
                    # r.disconnect()
                except Exception as err:
                    exception_type = type(err).__name__
                    self.error = self.msg[exception_type]
                    print("Error: ", self.msg[exception_type])
                    continue
            output = self.r.send_command(command)
            pattern = re.compile("eigrp")  # zakładamy, że outside jest widziany tylko po bgp i staticu (sprawdzić SIA)
            m = pattern.findall(output)
            if len(m) > 0:
                return 'inside'  # adres jest wewnetrzny
            pattern = re.compile("\*via ((?:\d+\.){3}\d+)")
            m = pattern.findall(output)
            if m[0] in route_core.keys():
                return route_core[m[0]]
            else:
                self.error = "Błąd podczas wyznaczania ścieżki. Nie wprowadzono żadnych zmian."
                print(f'Error: Not defined {m[0]} edge in route_core (looking for {ip})')
                return 0
        if not m:
            self.error = "Błąd połaczenia z routerami rdzeniowymi. Nie wprowadzono żadnych zmian."
            print('Error: Connection to all core routers failed')
            return 0


# Zakladamy, że może być wiele typów urządzeń brzegowych (na razie tylko Palo). Wprowadzamy nadklasę Edge, aby
# wymusić konstrukcję klas dla innych urządzeń. Funkcja get_zone zwraca coś co jest potrzebne do stworzenia
# reguły oprócz ip. Dla Palo są to zony. Dla ASA również.
class Edge:
    def get_zone(self, dst_ip):
        pass

    def get_compress2ag(self, a_list, name):
        pass


class Palo(Edge):
    """Komuikacja dla FW typu Palo Alto."""
    def __init__(self, edev, user, password):
        """
        :param edev: fwi, fwe, itp. - urządzenie brzegowe (jego symbol z tabeli route_core)
        """
        self.edev = edev
        self.devname = devinfo[edev][1]
        self.vsys = devinfo[edev][2]
        self.error = ''
        self.conn = Firewall(self.devname, api_username=user, api_password=password, vsys='vsys1')
        # obiekt Firewall powstanie nawet gdy nie powiedzie się uwierzytelnienie; nie pojawi się też żaden Exception
        # Poniższy show ma za zadanie sprowokować exception w przypadku, gdy coś jest nie tak z obiektem.
        try:
            self.conn.op("show system info")
        except PanDeviceError as err:
            self.error = err
            print(f'Error: Can not connect to {self.devname}: ', self.error)

    def get_zone(self, addr_ip):
        """wyznaczaa Zone dla adresu IP"""
        cmd = f'<test><routing><fib-lookup><virtual-router>{self.vsys}</virtual-router><ip>{addr_ip}</ip></fib-lookup>\
                </routing></test>'
        try:
            ans_gw = self.conn.op(cmd, cmd_xml=False)
        except PanDeviceError as err:
            self.error = err
            print(f'Error: Routing table from {self.devname}: ', self.error)
            raise regool.rgerrors.ChannelError(f'Problem z tablicą routingu na {self.devname}')
            return
        interface = ans_gw.find("./result/interface").text
        cmd = f'<show><interface>{interface}</interface></show>'
        ans_int = self.conn.op(cmd, cmd_xml=False)
        out_zone = ans_int.find("./result/ifnet/zone").text
        return out_zone

    def compress2ag(self, a_list, name):
        """Tworzy obiekt grupujący adresy ip (ag - address group)
        :param a_list: Lista z adresami IP
        :param name: Base Name, na podstawie której budowane są inne nazwy
        :returns: Nazwa obiktu grupy adresów
        """
        fw = self.conn
        agname = 'ag-' + name
        AddressObject.refreshall(fw, add=True)
        if len(a_list) > sec_max_ao:
            raise regool.rgerrors.ToManyElementsError(f'Ilość adresów do dodania przekracza ustalony próg {sec_max_ao}')
        ao2add = []
        for a in a_list:
            ao = fw.find(a, AddressObject)
            if ao is None:
                ao_name = a
                ao_ip = a.split('-')[1]
                ao = AddressObject(ao_name, ao_ip)
                ao2add.append(ao)
                fw.add(ao)
        if ao2add:
            ao2add[0].create_similar()
        AddressGroup.refreshall(fw, add=True)
        # teoretycznie tego ag nie powinno być, ale na wszelki wypadek sprawdzamy
        ag = fw.find(agname, AddressGroup)
        if ag is None:
            ag = AddressGroup(agname, ao2add)
            fw.add(ag)
            ag.create()
        else:
            raise regool.rgerrors.UnexpectedExistsError(f'Element {ag.name} istnieje chociaż nie powinien')
        return ag.name


class Connections():
    """Obiekt ogarniający wszystkie funkcje związane z dostępem do urządzeń sieciowych.
    self.connections_to_fw - lista połączeń do FW.
    self.rules_fullinfo - komplet informacji do konfiguracji reguł.
    """
    def __init__(self, table, user, password):
        """Wyznacza ścieżkę dla reguły, czyli device and zone.
        Funkcja wyznacza listę firewalli do konfiguracji i uzupełnia tabelę reguł o zony. I to w jednej pętli.
        To jest za dużo jak na init. Ale ta klasa jest przerubką z istniejącej wcześniej funkcji, która została
        dobrze przetestowana. Nie warto więc przerabiać.
        :param user, password: Credentials for login (tacacs)
        :param table: Lista list (tabela). Surowe dane z wniosku.
                    [[src, dst, port], ...]
        :returns: Do każdego wiersza z tabeli wejściowej dodawane są informacje o dev i zone wg wzoru:
                    [[dev, src_ip, src_zone, dst_ip, dst_zone, port], ...]
        """
        # table zawiera porty, interesują nas tutaj tylko adresy ip, więc porty odrzucamy
        ipset = [a[slice(0, 2)] for a in table]
        router = Coredev(user, password)
        self.rules_fullinfo = []
        self.connections_to_fw = []
        for p in ipset:
            edge_dev = []
            for i in range(0, 2):
                # wyznaczanie firewall'i do konfiguracji dla pary src dst (z routerów corowych)
                ip = p[i]
                ip_to_find = ip.split('/')[0]
                found = router.find_edge(ip_to_find)
                if not found:
                    print(router.error)
                    raise regool.rgerrors.ChannelError(router.error)
                if found != "inside":
                    # jeśli inside, to tylko jeden fw do konfiguracji
                    edge_dev.append(found)
            # Jeśli dostęp musi być konfigurowany na dwóch fw, to edge_dev będzie zawierał dwa elementy.
            # Jeśli na jednym - to jeden. Czyli poniższa pętla przekręci się raz lub dwa razy.
            for edev in edge_dev:
                # mając firewale z pętli wyżej, zestawiamy połaczenia do nich, wyznaczamy zony dla każdej pary ip
                fw_row_ininfo = []
                for i in range(0, 2):
                    ip = p[i]
                    fw_row_ininfo.append(ip)
                    ip_to_find = ip.split('/')[0]
                    if not isinstance(devinfo[edev][1], eval(devinfo[edev][0])):
                        # poniższa skomplikowany algorytm wynika z założenia, że mamy wiele typów urządzeń brzegowych
                        klass = eval(devinfo[edev][0])
                        devinfo[edev][1] = klass(edev, user, password)
                        self.connections_to_fw.append(devinfo[edev][1])
                        # od tej pory devinfo[edge_dev][1] staje się obiektem
                        # pokazuje strukturę obiektu: print(devinfo[edev][1].__dict__)
                        if devinfo[edev][1].error:
                            # ten wyjątek nie jest przechwytywany wyżej
                            # należy jeszcze dodać logowanie
                            # print(f'Błąd połączenia z firewallem {edev}. Nie wprowadzono żadnych zmian')
                            raise regool.rgerrors.ChannelError(f'Błąd połączenia z firewallem {edev}')
                    try:
                        zone = devinfo[edev][1].get_zone(ip_to_find)
                    except regool.rgerrors.ChannelError:
                        # print(f'Błąd podczas wyznaczania ścieżki dla {ip_to_find}. Nie wprowadzono żadnych zmian.')
                        raise regool.rgerrors.ChannelError(f'Błąd podczas wyznaczania ścieżki dla {ip_to_find}.')
                    fw_row_ininfo.append(zone)
                # fw_row_ininfo.insert(0, edev)
                fw_row_ininfo.insert(0, edev)
                fw_row_ininfo.append(table[1][2])
                self.rules_fullinfo.append(fw_row_ininfo)
