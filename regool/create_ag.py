import sys
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressObject, AddressGroup
#from panos.errors import PanObjectError
import panos.errors
from rich import inspect
from regool.input_data import validate_ip, validate_fqdn
import config
""" Tworzy ag jeśli liczba ao w regule jest większa niż ao_max. Podstawia nazwę nowej ag zamiast listy ao.
input: optitable_aos: {'fw-01': [['inside', 'outside', ['net-1-10.3.135.0-24'], ['srv_a-1-172.31.1.72', 'srv_a-2-172.31.1.73', 'srv-3-172.31.1.74', 'master_server-172.31.1.75', 'sys.int.fmr.com'], ['80'],
output: optitable_ags:
"""
HOSTNAME = "172.0.0.1"
USERNAME = "apiuser"
PASSWORD = "*****"
#Zakładamy, że szablonów może być kilka. Proefix nazwy szablonu może być inny niż reguły
rule_tmpl_prefix = 'rt7744'
rule_prefix = 'r7744'
tmpl_name = 'default'
input_id = '109557' #id wniosku do zrealizowania
ao_max = 4
convention = config.convention
def main():
    optitable_aos = {'fw-01': [['inside', 'outside', ['net-1-10.3.135.0-24'], ['srv_a-1-172.31.1.72', 'srv_a-2-172.31.1.73', 'srv-3-172.31.1.74', 'master_server-172.31.1.75', 'sys.int.fmr.com'], ['80'], ''], ['inside', 'outside',
['net-1-10.3.135.0-24'], ['srv-3-172.31.1.74'], '', ['ping']]]}
    fw = Firewall(HOSTNAME, USERNAME, PASSWORD)
    aos = AddressObject.refreshall(fw, add=True)
    ags = AddressGroup.refreshall(fw, add=True)
    ag_ao_list = []
    ag = AddressGroup()
    i=0
    for dev in optitable_aos.keys():
        for rule in optitable_aos[dev]:
            idx1 = optitable_aos[dev].index(rule) #index ruli
            for pos_in_rule in [2,3]: #2 for src and 3 for dst in optitable
                if len(rule[pos_in_rule]) > ao_max:
                    i += 1
                    agname = convention['addr-group-prefix'] + '-' + input_id + '-' + str(i)
                    for ao_name in rule[pos_in_rule]:
                        ao = fw.find(ao_name,  AddressObject)
                        ag_ao_list.append(ao)
                    # teoretycznie tego ag nie powinno być, ale na wszelki wypadek sprawdzamy
                    ag = fw.find(agname, AddressGroup)
                    if ag is None:
                        ag = AddressGroup(agname, ag_ao_list)
                        fw.add(ag)
                        rule[pos_in_rule] = []
                        rule[pos_in_rule].append(agname)
                    else:
                        err = f'Element {agname} istnieje chociaż nie powinien'
                        print(err)
                        exit()
    if ag_ao_list:
        try:
            ag.create_similar()
        except panos.errors.PanDeviceError as e:
            err = f'Can not create address group objects: {e}'
            print(err)
            exit()
    fw.commit()
    print(optitable_aos)
 
if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        main()