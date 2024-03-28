import os
import sys
import regool.rgerrors as err

# import ipaddress
from regool.logger_setup import logger
import re
import csv


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
                    or not validate_port(row[4])
                ):
                    raise err.EntryDataError(
                        f"Invalid format of IP address in entry data."
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


def validate_port(port):
    """
    Validates format of service ports. It can be: 80,443,samba, 7000-8000
    """
    ports = port.split(",")
    pattern = r"^[a-zA-Z0-9]{1,6}$|^\d+-\d+$"
    for p in ports:
        p.strip()
        match = re.match(pattern, p)
        if not match:
            logger.error(f"The TCP port or service name {p} is invalid")
            return False
    return True
