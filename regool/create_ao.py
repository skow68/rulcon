import sys
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressObject, AddressGroup
#from panos.errors import PanObjectError
import panos.errors
from rich import inspect
from regool.input_data import validate_ip, validate_fqdn
import config
"""Tworzy obiekty ao z optitable. Zamienia ip na obiekty i konfiguruje na fw. Wcześniej sprawdzamy, czy już są takie obiekty.
input: optitable: {'fw-01': [['inside', 'outside', ['10.143.135.20'], ['172.31.1.72', '172.31.1.73', '172.31.1.74'], ['80'], ''], ...
output: optitable_aos: {'fw-01': [['inside', 'outside', ['srv1-10.143.135.20'], ['srv2-172.31.1.72', 'srv3-172.31.1.73', 'srv-4-172.31.1.74'], ['80'], ''],
"""
HOSTNAME = "172.0.0.1"
USERNAME = "apiuser"
PASSWORD = "*****"
#Zakładamy, że szablonów może być kilka. Proefix nazwy szablonu może być inny niż reguły
rule_tmpl_prefix = 'rt7744'
rule_prefix = 'r7744'
tmpl_name = 'default'
input_id = '109557' #id wniosku do zrealizowania
 
def main():
    optitable = {'fw-01': [['inside', 'outside', ['10.3.135.0/24'], ['172.31.1.72', '172.31.1.73', '172.31.1.74', '172.31.1.75', 'sys.int.fmr.com'], ['80'], ''],
    ['inside', 'outside', ['10.3.135.0/24'], ['172.31.1.74'], '', ['ping']]]}
    dns = {'10.3.135.0/24': 'net-1', '172.31.1.72': 'srv_a-1', '172.31.1.73': 'srv_a-2', '172.31.1.74': 'srv-3', '172.31.1.75': "master_server"}
    fw = Firewall(HOSTNAME, USERNAME, PASSWORD)
    aos = AddressObject.refreshall(fw, add=True)
    ags = AddressGroup.refreshall(fw, add=True)
    is_new_ao = False
    ao = AddressObject()
    for dev in optitable.keys():
        for rule in optitable[dev]:
            idx1 = optitable[dev].index(rule)
            for pos_in_rule in [2,3]: #2 for src and 3 for dst in optitable
                for ip in rule[pos_in_rule]:
                    if validate_ip(ip):
                        type = 'ip-netmask'
                        ip_parts = ip.split('/')
                        if '/' in ip:
                            ao_name = dns[ip] + '-' + ip_parts[0] + '-' + ip_parts[1]
                        else:
                            ao_name = dns[ip] + '-' + ip
                    elif validate_fqdn(ip):
                        ao_name = ip
                        type = 'fqdn'
                    else:
                        print("Something wrong with validating input data")
                        exit()
                    is_ao = fw.find(ao_name,  AddressObject)
                    if not is_ao:
                        print(f'Object to add: {ao_name}')
                        ao = AddressObject(ao_name, ip, type)
                        is_new_ao = True
                        fw.add(ao)
                    idx = optitable[dev][idx1][pos_in_rule].index(ip)
                    optitable[dev][idx1][pos_in_rule][idx] = ao_name
    if is_new_ao:
        try:
            ao.create_similar()
        except panos.errors.PanDeviceError as e:
            err = f'Can not create address objects: {e}'
            print(err)
            exit()
    fw.commit()
    print(optitable)
   
   
    #current_security_rules = SecurityRule.refreshall(rulebase)
if __name__ == "__main__":
    # This script doesn't take command line arguments.  If any are passed in,
    # then print out the script's docstring and exit.
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        # No CLI args, so run the main function.
        main()