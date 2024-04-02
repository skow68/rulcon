import os
import sys
import rgerrors as err
 
# import ipaddress
from logger_setup import logger
import re
import csv

combine_tcp_ports = True 
combine_udp_ports = True 
min_dif = 10 #różnica między portami, aby uznać ich podobnymi
min_nr_to_compress = 3 # min. liczba kolejnych podobnych portów, aby ich komprespwać do zakresu
 
def get_rules(file_name):
    """
    Obsługa danych wejściowych zawierających reguły do wprowadzenia w formacie src_name-src_ip-dst_name-dst_ip-dst_port.
    Wykonywana jest również weryfikacja poprawności formatu poszczególnych pól.
    Args:
    file_name (str): The name of the file.
    Returns:
    list of lists: lista reguł; reguła to lista w formacie jak wyżej.
    """
    if os.path.isfile(file_name):
        parts = file_name.split(".")
        # If there's more than one part, return the last part (which represents the extension)
        if len(parts) > 1:
            extension = parts[-1]
        else:
            logger.error("Plik wejściowy nie ma rozszerzenia")
            raise err.EntryDataError("Plik wejściowy musi mieć rozszerzenie.")
            sys.exit(1)
        with open(file_name, "r") as file:
            if extension == "csv":
                reader = csv.reader(file, delimiter=";")
                input_rules = [row for row in reader]
            elif extension == "xls":
                """
                import openpyxl
                workbook = openpyxl.load_workbook(file)
                worksheet = workbook["Arkusz1"]
                my_dns = {}
                basetable = []
                for row in worksheet.iter_rows(values_only = True, min_row=3):
                    my_dns[row[1]] = row[0]
                    my_dns[row[2]] = row[3]
                    dst = row[3]
                    src = row[1]
                    port = row[4]
                    basetable.append([src, dst, port])
                """
                print("to be done")
            for row in input_rules:
                if (
                    not validate_fqdn(row[0])
                    or not validate_ip(row[1])
                    or not validate_fqdn(row[2])
                    or not validate_ip(row[3])
                    or not validate_service(row[4])
                ):
                    raise err.EntryDataError(
                        f"Invalid format of host or network address in entry data."
                    )
                    sys.exit(1)
        return input_rules
    else:
        logger.error(f"Can not find entry file: {file_name}")
        raise err.EntryDataError(f"Can not find entry file: {file_name}")
        sys.exit(1)
 
 
def validate_ip(ip_address):
    """
    Args:
    ip_adress (str): I address
    Returns:
    True/False: format of IP address is correct or not
    """
    ip_pattern = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((?:/\d{1,2}))?$"
    match = re.match(ip_pattern, ip_address)
    if match:
        octets = match.group(1).split(".")  # Extract octets
        network_length = (
            int(match.group(2)[1:]) if match.group(2) else None
        )  # Extract network length
        # Check if octet values are in the range of 0-255 and network length is in the range of 0-32
        if all(0 <= int(octet) <= 255 for octet in octets) and (
            network_length is None or 0 <= network_length <= 32
        ):
            return True
        else:
            #logger.error(f"The IP address {ip_address} is invalid")
            return False
    else:
        #logger.error(f"The IP address {ip_address} is invalid")
        return False
 
 
def validate_fqdn(fqdn):
    """
    Simple validation for now. Not realu fqdn.
    """
    # fqdn_pattern = r'^(?:\w+://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    fqdn_pattern = r"[a-zA-Z0-9.-]+"
    match = re.match(fqdn_pattern, fqdn)
    if match:
        return True
    else:
        #logger.error(f"Address {fqdn} is invalid")
        return False
 
def combine_tcp_ports(portlist):
    """Wychwytywanie ciągów portów różniących się niewiele i które można zamienić na zakres
    min_dif - różnica między portami, aby można potraktować ich jako podobne
    min_nr_to_compress - min. liczba kolejnych podobnych portów, aby warto komprespwać do zakresu
    input: lista portów jako lista liczb
    output: list par indeksów listy portów oznaczających początek i koniec zakresu
    """
    portlist.sort()
    dif = []
    for i in range(0, len(portlist) - 1):
        tab = portlist[i::1]
        dif.append(int(tab[1]) - int(tab[0]))
    pairs = []
    x = 0
    start = 0
    stop = 0
    rang = False
    for i in range(0, len(dif)):
        if dif[i] <= min_dif:
            x += 1
            if i == len(dif) - 1: #obsługa warunku brzegowego; gdy porty są na samym końcu
                stop = i + 2
                start = i - x + 1
                pairs.append([start,stop])
        else:
            x = 0
        if x >= min_nr_to_compress - 1:
            start = i - x + 1
            rang = True
        elif x < min_nr_to_compress - 1 and rang:
            stop = i - x + 1
            pairs.append([start,stop])
            rang = False
    return pairs

def combine_udp_ports(portlist_udp):
    """Wychwytywanie ciągów portów różniących się niewiele i które można zamienić na zakres
    min_dif - różnica między portami, aby można potraktować ich jako podobne
    min_nr_to_compress - min. liczba kolejnych podobnych portów, aby warto komprespwać do zakresu
    input: lista portów jako lista liczb
    output: list par indeksów listy portów oznaczających początek i koniec zakresu
    """
    portlist_udp.sort()
    dif = []
    for i in range(0, len(portlist_udp) - 1):
        tab = portlist_udp[i::1]
        dif.append(int(tab[1]) - int(tab[0]))
    pairs_udp = []
    x = 0
    start = 0
    stop = 0
    rang = False
    for i in range(0, len(dif)):
        if dif[i] <= min_dif:
            x += 1
            if i == len(dif) - 1: #obsługa warunku brzegowego; gdy porty są na samym końcu
                stop = i + 2
                start = i - x + 1
                pairs_udp.append([start,stop])
        else:
            x = 0
        if x >= min_nr_to_compress - 1:
            start = i - x + 1
            rang = True
        elif x < min_nr_to_compress - 1 and rang:
            stop = i - x + 1
            pairs_udp.append([start,stop])
            rang = False
    return pairs_udp

def validate_service(portstr):
    """
    Validates format of service ports. It can be: 80,443, 7000-8000, 53/udp, 9000-9010/udp
    Nie tylko waliduje, ale od razu zamienia na nazwy service object zgodnie z konwencją:
    ['tcp-80', 'tcp-443', 'tcp-7000-8000', 'udp-53', 'tcp-2001', 'tcp-2002', 'tcp-2003', 'udp-9000-9010/udp']
    """
    ports = portstr.split(",")
    output = []
    portlist = []
    portlist_udp = []
    #pattern = r"^[a-zA-Z0-9]{1,6}$|^\d+-\d+$"
    idx = 0
    for p in ports:
        p = p.strip()
        pattern = r"^\d+$"
        #65535
        start = len(output)
        match = re.match(pattern, p)
        if match:
            if int(p) < 65536:
                output.append('tcp-' + p)
                if int(p) > 1024:
                    portlist.append(int(p))
            else:
                try:
                    raise err.EntryDataError(f"UDP range not correct: {p}")
                except err.EntryDataError:
                    sys.exit(1)
        pattern = r"^\d+-\d+$"
        match = re.match(pattern, p)
        if match:
            parts = p.split('-')
            if int(parts[0]) < 65536 and int(parts[1]) < 65536 and int(parts[0]) < int(parts[1]):
                output.append('tcp-' + p)
            else:
                try:
                    raise err.EntryDataError(f"UDP range not correct: {p}")
                except err.EntryDataError:
                    sys.exit(1)
        pattern = r"^(\d+)\/udp$"
        match = re.match(pattern, p)
        if match:
            m = int(match.group(1))
            if m < 65536:
                output.append('udp-' + str(m))
                if m > 1024:
                    portlist_udp.append(m)
            else:
                try:
                    raise err.EntryDataError(f"UDP range not correct: {p}")
                except err.EntryDataError:
                    sys.exit(1)
        pattern = r"^(\d+-\d+)\/udp$"
        match = re.match(pattern, p)
        if match:
            pp = match.group(1)
            parts = pp.split('-')
            if int(parts[0]) < 65536 and int(parts[1]) < 65536 and int(parts[0]) < int(parts[1]):
                output.append('udp-' + pp)
            else:
                try:
                    raise err.EntryDataError(f"UDP range not correct: {p}")
                except err.EntryDataError:
                    sys.exit(1)
        stop = len(output)
        if stop - start == 0:
            logger.error(f"At least one of the TCP/UDP port is invalid")
            return False
    # wychwytywanie ciągów portów różniących się niewiele i które można zamienić na zakres
    if combine_tcp_ports:
        pairs = combine_tcp_ports(portlist)
        for pair in pairs:
            slice_of_portlist = portlist[int(pair[0]):int(pair[1])]
            for s in slice_of_portlist:
                output.remove('tcp-' + str(s))
            rangetcp = 'tcp-' + str(portlist[pair[0]]) + '-' + str(portlist[pair[1]-1])
            output.append(rangetcp)
    if combine_udp_ports:
        pairs_udp = combine_udp_ports(portlist_udp)
        for pair in pairs_udp:
            slice_of_portlist_udp = portlist_udp[int(pair[0]):int(pair[1])]
            for s in slice_of_portlist_udp:
                output.remove('udp-' + str(s))
            rangeudp = 'udp-' + str(portlist_udp[pair[0]]) + '-' + str(portlist_udp[pair[1]-1])
            output.append(rangeudp)
        return output
 
if __name__ == "__main__":
    input = '2008, 1500/udp, 1502/udp, 1503/udp, 80,443, 7000-8000, 53/udp, 2000, 2010, 8010, 8020, 8030, 9000-9010/udp'
    #input = '80, 7000-8000'
    validated = validate_service(input)
    print(validated)