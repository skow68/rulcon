from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressGroup, AddressObject, ServiceObject, ApplicationObject, ServiceGroup, ApplicationGroup
import regool.textui
import regool.rgerrors as err
import config
""" Czy reguły z wniosku pasują do już istniejących reguł. Sprawdzane są dst ip, dst srv i dst app. Jeśli dst z wniosku zawierają się w dst z fw,
to do tej reguły dodawane są src ip z wniosku.
Service Group i Application Group - czy przeszukujemy wszystkie nazwy, nie tylko zgodne z konwencją, dlatego, że admin może tworzyć pewne uniwersalne grupy,
   wykorzystywane następnie w wielu regułach? Nie. Reguły zarządzane przez aplikację powinny stanowić oddzielne królestwo.
input: optitable
"""
optitable = {'fw-01': [{'fromzone': 'inside', 'tozone': 'outside', 'source': ['10.3.135.0/24'], 'destination': ['172.31.1.72', '172.31.1.73', '172.31.1.74', '172.31.1.75', 'sys.int.fmr.com'], 'service': ['80', '443', '2001', '2002', '2003'], 'application': ''},
    {'fromzone': 'inside', 'tozone': 'outside', 'source': ['10.3.135.0/24'], 'destination': ['172.31.1.74'], 'service': '', 'application': ['ping']}]}
# Create config tree and refresh rules from live device
kindom = config.convention['security-rule-prefix']
fw = Firewall("172.0.0.1", "apiuser", "********")
#print(fw.op("show system info"))
rulebase = fw.add(Rulebase())
live_rules = SecurityRule.refreshall(rulebase) # do przegrepowania po prefixie dla rul
live_ags = AddressGroup.refreshall(fw, add=True)
tabela = regool.textui.Tabela()
lr_digest = {}
def decompress_addr(addr_list):
    """
    Decompresses a list of addresses by expanding any AddressGroup objects into their individual members.
    Args: addr_list (list): A list of addresses, which may contain AddressObject or AddressGroup objects.
    Returns: list: A list of decompressed addresses, where any AddressGroup objects have been expanded into their individual members.
    """
    decompressed_list = []
    for addr in addr_list:
        if isinstance(addr, AddressObject):
            decompressed_list.append(addr)
        elif isinstance(addr, AddressGroup):
            decompressed_list.extend([obj for obj in addr.members])
    return decompressed_list
def decompress_srv(srv_list):
    """
    Decompresses a list of service objects and service groups.
    Args:        srv_list (list): A list of service objects and service groups.
    Returns:        list: A list of decompressed service objects.
    """
    decompressed_list = []
    for srv in srv_list:
        if isinstance(srv, ServiceObject):
            decompressed_list.append(srv)
        elif isinstance(srv, ServiceGroup):
            decompressed_list.extend([obj for obj in srv.members])
    return decompressed_list
def decompress_app(app_list):
    """
    Decompresses the given list of applications.
    Args:        app_list (list): A list of applications to decompress.
    Returns:        list: A list of decompressed applications.
    """
    decompressed_list = []
    for app in app_list:
        if isinstance(app, ApplicationObject):
            decompressed_list.append(app)
        elif isinstance(app, ApplicationGroup):
            decompressed_list.extend([obj for obj in app.members])
    return decompressed_list
def modify_rule(rule_name, src_list):
    """
    Modifies the given rule by adding the source addresses from the given list.
    Args:        rule_name (str): The name of the rule to modify.        src_list (list): A list of source addresses to add to the rule.
    """
    rule = fw.find(rule_name, SecurityRule)
    if rule is None:
        raise err.RuleNotFoundError(rule_name)
    for src in src_list:
        rule.source.append(src)
    rule.apply()
#po przeniesieniu do paths.py tutaj musi być jeszcze pętla po dev
for lr in live_rules:
    if not lr.name.startswith(kindom) or lr.action != "allow":
         next()
    lr_digest[lr.name] = [lr.source, lr.fromzone, lr.destination, lr.tozone, lr.service, lr.application, lr.action]
    lr_dst_aos = decompress_addr(lr.destination)
    lr_dst_srv = decompress_srv(lr.services)
    lr_dst_app = decompress_app(lr.application)
    lr_src_aos = decompress_addr(lr.source)
    for opti_rule in optitable[fw.hostname]:
        #czy zawiera ag? jeden czy więcej? może to być ag, które jest wykorzystywane w innych rulach, czyli nie możemy tak po prostu coś dodać
        # chyba że zdecydujemy, ze dane ag jest związane z daną rulą
        #if opti_rule[3].lenght == 1 and fw.find(opti_rule[3][0], AddressGroup): #jeden element, czyli jest szansa, że to ag
        #czy dst z optitable zawiera się w dst z fw:
        if set(opti_rule['destination']).issubset(lr_dst_aos) and set(opti_rule['service']).issubset(lr_dst_srv) and set(opti_rule['application']).issubset(lr_dst_app):
            modify_rule(lr.name, opti_rule['source'])
            #tutaj należy usunąć regułę z optitable, żeby nie była przetwarzana ponownie
            optitable[fw.hostname].remove(opti_rule)
 
 
 
#[[dev, src_ip, src_zone, dst_ip, dst_zone, port, app], ...] - input z optymalizatora