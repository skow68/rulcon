#!/usr/bin/env python3
# import sys
import re
import warnings
import sys
import regool.rgerrors
from netmiko import SSHDetect, ConnectHandler
from netmiko.cisco import CiscoNxosSSH  # tylko dla funkcji isinstance
from panos.errors import PanCommitNotNeeded, PanDeviceError, PanObjectMissing, PanURLError, PanApiKeyNotSet
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressObject, AddressGroup
from regool.logger_setup import logger
import config
firewalls = config.firewalls
route_source = config.route_source
routes_to_outside = config.route_to_outside
convention = config.convention
# warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
warnings.filterwarnings('ignore', '.*deprecated.*')

sec_max_ao = 2
#route_src_conns = []
class Cisco():
    """Connection to Cisco devices
    """
    def __init__(self, host):
        coredev = {
            #"device_type": "cisco_Nxos_ssh",
            'host': route_source[host]['name'],
            "device_type": "autodetect",
            "username": user,
            "password": password,
            "session_log": "net-core.log",
        }
        self.msg = {
            'NetmikoAuthenticationException': 'Authentication error',
            'NetmikoTimeoutException': 'Timeout error',
        }
        try:
            guesser = SSHDetect(**coredev)
            best_match = guesser.autodetect()
            print(best_match)
            print(guesser.potential_matches)
            # Update the 'device' dictionary with the device_type
            coredev["device_type"] = best_match
            self.host = ConnectHandler(**coredev)
            # print(r.__dict__)
            # r.disconnect()
        except Exception as err:
            exception_type = type(err).__name__
            self.error = self.msg[exception_type]
            logger.info(self.msg[exception_type])

        def show_ip_route(self, ip):
            """
            :param ip: adres, dla którego szukamy gatewaya
            :return: gateway dla IP wejściowego
            """
            command = f'show ip route {ip}'
            output = self.host.send_command(command)
            pattern = re.compile("\*via ((?:\d+\.){3}\d+)")
            m = pattern.findall(output)
            return m[0]
        #Po co to?:
        #self.error = ''
        #for i in config['core']:
    #    self.core = i
def find_edge(ip):
    """Na podstawie routing wyznacza firewall'e, na których należy wykonać konfigurację
    Wydruki błędów należy zamienić logowaniem.
    Sygnalizpwanie błędów należy zamienić na try expect
    :param ip: adres IP, o którym mamy się dowiedzieć, czy jest wewnętrzny, czy zewnętrzny, a jeśli zewnętrzny,
     to za jakim firewallem się znajduje
    :return: nazwa firewall'a, przez który IP wejściowy jest dostępny lub "inside", jeśli jest to IP wewnętrzny
    """
    
    #We assume that needed routing is not necessairly available in all route sources. It may only exists in one.
    #So, we need loop over listed devices until the proper routing is found.
    ip_to_edge_dev = []
    for r in route_source:
        #The function may be executed multiple times. We want to avoid setting up more than one session for a single device.
        #If the first route source in config list knows all routes, then only one connection is established. The rest of
        #route sources are engaged if the first one doesn't know route we are looking for.
        if not isinstance(route_source[r]['name'], eval(route_source[r]['type'])):
            # print("Creating new netmiko object")
            klass = eval(route_source[r]['type'])
            route_source[r]['name'] = klass(r)
            #route_src_conns.append(r)
        ip_to_edge_dev = route_source[r]['name'].show_ip_route(ip)
        #Simply having a routing path to the target IP is not enough. It must point at a firewall.
        if ip_to_edge_dev in routes_to_outside.keys():
            return routes_to_outside[ip_to_edge_dev]
    #If ip_to_edge_dev exists, it means that at least one core device was accessible. It's sufficient condition
    #to conclude that required routing was not found. It means that the IP address we are searching for must be an inside IP.
    if ip_to_edge_dev is False:
        #Jeśli chociaż jeden route source odpowiedział, to ip_to_edge_dev musi coś zawierać
        error = "Błąd połączenia z routerami rdzeniowymi. Nie wprowadzono żadnych zmian."
        print('Error: Connection to all sources of routes failed')
        raise regool.rgerrors.NoRouteSource('Connection to all sources of routes failed')
        logger.error("Connection to all sources of routes failed")
        sys.exit(1)
    return 'inside'
# Zakladamy, że może być wiele typów urządzeń brzegowych (na razie tylko Palo). Wprowadzamy nadklasę Edge, aby
# wymusić konstrukcję klas dla innych urządzeń. Funkcja get_zone zwraca coś co jest potrzebne do stworzenia
# reguły oprócz ip. Dla Palo są to zony. Dla ASA również.
class Edge:
    def get_zone(self, dst_ip):
        pass

    def get_compress2ag(self, a_list, name):
        pass


class Palo(Edge):
    """Komuikacja dla FW typu Palo Alto.
    Instancja obiektu pozwala na komunikację z urządzeniem dzięki "conn". To nie są połączenia w sensie sesji tcp, bo
    mamy tu do czynienia z API po http. Są to sesje w sensie uwierzytelnienia. 
    """
    def __init__(self, fw):
        """
        :param fw: fwi, fwe, itp. - urządzenie brzegowe (jego symbol z edge_devices)
        """
        self.fw = fw
        self.devname = firewalls[fw]['name']
        self.vsys = firewalls[fw]['vsys']
        self.conn = Firewall(self.devname, api_username=user, api_password=password, vsys='vsys1')
        # obiekt Firewall powstanie nawet gdy nie powiedzie się uwierzytelnienie; nie pojawi się też żaden Exception
        # Poniższy show ma za zadanie sprowokować exception w przypadku, gdy coś jest nie tak z obiektem.
        try:
            self.conn.op("show system info")
        except PanDeviceError as e:
            err = f'Can not connect to {self.devname}:  {e}'
            logger.error(err)
            raise regool.rgerrors.ConnectError(err)
            sys.exit(1)

    def get_zone(self, addr_ip):
        """wyznaczaa Zone dla adresu IP"""
        cmd = f'<test><routing><fib-lookup><virtual-router>{self.vsys}</virtual-router><ip>{addr_ip}</ip></fib-lookup>\
                </routing></test>'
        try:
            ans_gw = self.conn.op(cmd, cmd_xml=False)
        except PanDeviceError as e:
            err = f'Can not get routing table from {self.devname}: {e}'
            logger.error(err)
            raise regool.rgerrors.GetZoneError(err)
            sys.exit(1)
        interface = ans_gw.find("./result/interface").text
        cmd = f'<show><interface>{interface}</interface></show>'
        ans_int = self.conn.op(cmd, cmd_xml=False)
        out_zone = ans_int.find("./result/ifnet/zone").text
        return out_zone

    def create_ag(self, a_list, name):
        """Tworzy obiekt grupujący adresy ip (ag - address group)
        :param a_list: Lista z adresami IP
        :param name: Base Name, na podstawie której budowane są inne nazwy np. ID wniosku
        :returns: Nazwa obiktu grupy adresów
        """
        fw = self.conn
        agname = convention['addr-group-prefix'] + name
        AddressObject.refreshall(fw, add=True)
        if len(a_list) > config.limits['max_ao_in_ag']:
            err = f'Ilość adresów do dodania przekracza ustalony próg {config.limits["max_ao_in_ag"]}'
            logger.error(err)
            raise regool.rgerrors.ToManyElementsError(err)
            sys.exit(1)
        ao2add = []
        for a in a_list:
            ao = fw.find(a, AddressObject)
            #zakładamy, że nazwa ao jest zgodna z wzorem nazwa-adres_ip
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
            err = f'Element {ag.name} istnieje chociaż nie powinien'
            logger.error = err
            raise regool.rgerrors.UnexpectedExistsError(err)
        return ag.name
    def create_sg(self, s_list, name):
        #to be done
        return


class Connections():
    """Obiekt do utrzymywania połączeń do firewall'i zaangażowanych do konfiguracji reguł dla konkretnej pary IP.
    Na wejście dostajemy tabelę składającą się z wszystkich wierszy jednego wniosku. Czyli ten obiekt jest wniosko-centryczny
    Całą robotę wykonuje init tworząc:
    self.connections_to_fw - lista zestawionych połączeń do FW.
    self.rules_fullinfo - komplet informacji do konfiguracji reguł tzn. z zonami i na jakim firewallu 
    """
    def __init__(self, table):
        """Wyznacza ścieżkę dla reguły, czyli device and zone.
        Funkcja wyznacza listę firewalli do konfiguracji i uzupełnia tabelę reguł o zony. I to w jednej pętli.
        To jest za dużo jak na init. Ale ta klasa jest przeróbką z istniejącej wcześniej funkcji, która została
        dobrze przetestowana. Nie warto więc przerabiać.
        :param table: Lista list (tabela). Surowe dane z wniosku.
                    [[src, dst, port], ...]
        :returns: Do każdego wiersza z tabeli wejściowej dodawane są informacje o dev i zone wg wzoru:
                    [[dev, src_ip, src_zone, dst_ip, dst_zone, port], ...]
        """
        # table zawiera porty, interesują nas tutaj tylko adresy ip, więc porty odrzucamy
        ipset = [a[slice(0, 2)] for a in table]
        self.rules_fullinfo = []
        self.connections_to_fw = []
        for row in ipset:
            fw_to_conf = []
            inside_counter = 0 #licznik wystąpienia IP w Inside
            for i in range(0, 2):
                # Wyznaczanie firewall'i do konfiguracji dla pary src dst (z routerów corowych)
                ip = row[i]
                ip_to_find = ip.split('/')[0]
                found = find_edge(ip_to_find)
                if found != "inside":
                    # jeśli inside, to tylko jeden fw do konfiguracji
                    fw_to_conf.append(found)
                else:
                    inside_counter += 1
            if inside_counter > 1:
                err = "SRC IP oraz DST IP znajdują się w strefie INSIDE. Nieprawidłowo sformułowana reguła dostępowa."
                logger.erro(err)
                raise regool.rgerrors.EntryDataError('Nieprawidłowo sformułowana reguła dostępowa.')
                sys.exit(1)
            # Jeśli dostęp musi być konfigurowany na dwóch fw, to fw_to_conf będzie zawierał dwa elementy.
            # Jeśli na jednym - to jeden. Czyli poniższa pętla przekręci się raz lub dwa razy.
            for fw in fw_to_conf:
                # Mając firewale z pętli wyżej(jeden lub dwa), zestawiamy połaczenia do nich, wyznaczamy zony dla każdej pary ip.
                # Na każdym z tych firewalli dodajemy prawie taką samą regułę. Różnić się będą tylko nazwami zon.
                fw_row_ininfo = []
                for i in range(0, 2):
                    ip = row[i]
                    fw_row_ininfo.append(ip)
                    ip_to_find = ip.split('/')[0]
                    if not isinstance(firewalls[fw]['name'], eval(firewalls[fw]['type'])):
                        # poniższa skomplikowany algorytm wynika z założenia, że mamy wiele typów urządzeń brzegowych
                        klass = eval(firewalls[fw]['type'])
                        firewalls[fw]['name'] = klass(fw)
                        self.connections_to_fw.append(firewalls[fw]['name'])
                        # od tej pory firewalls[fw_to_conf][1] staje się obiektem
                        # pokazuje strukturę obiektu: print(firewalls[fw][nazwa].__dict__)
                    zone = firewalls[fw]['name'].get_zone(ip_to_find)
                    fw_row_ininfo.append(zone)
                # fw_row_ininfo.insert(0, fw)
                fw_row_ininfo.insert(0, fw)
                fw_row_ininfo.append(table[1][2])
                self.rules_fullinfo.append(fw_row_ininfo)
