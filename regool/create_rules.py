import sys
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressObject, AddressGroup
#from panos.errors import PanObjectError
import panos.errors
import regool.textui
"""Tworzy rulę z użyciem szablonu.
input: optitable_aos = {'fw-01': [['inside', 'outside', ['net-1-10.3.135.0-24'], ['srv_a-1-172.31.1.72', 'srv_a-2-172.31.1.73', 'srv-3-172.31.1.74', 'master_server-172.31.1.75', 'sys.int.fmr.com'], ['80'], ''], ...
czyli z podmienionymi src i dst na ao lub ag.
"""
HOSTNAME = "172.0.0.1"
USERNAME = "apiuser"
PASSWORD = "*****"
#Zakładamy, że szablonów może być kilka. Proefix nazwy szablonu może byćinny niż reguły
rule_tmpl_prefix = 'rt7744'
rule_prefix = 'r7744'
rule_tmpl_name = 'default' #admin będzie musiał podać podczas uruchamiania lub wymyśleć jakąś automatyczną regułę
input_id = '109557' #id wniosku do zrealizowania
# wzięte z dokumentacji pan-os-python; te parametry kopiujemy z szablonu
rule_params = ['source_user', 'hip_profiles', 'category', 'log_setting', 'log_start', 'log_end', 'type', 'tag', 'negate_source',
                'negate_destination', 'icmp_unreachable', 'disable_server_response_inspection', 'group', 'negate_target', 'target',
                  'virus', 'spyware', 'vulnerability', 'url_filtering', 'file_blocking', 'wildfire_analysis', 'data_filtering',
                    'group_tag', 'action']
def copy_rule_params(rule):
    copied = {}
    for p in rule_params:
        copied[p] = getattr(rule, p)
    return copied
#def main():
#[[dev, src_ip, src_zone, dst_ip, dst_zone, port, app], ...] - input z optymalizatora, ale po uzupełnieniu o nazwy
#
#optitable_aos = {'HOSTNAME': [['OUTSIDE', 'INSIDE', ['src_srv-1-10.3.135.20'], ['dst_srv-1-172.31.1.73', 'dst_srv_2-172.31.1.74', 'net-3-172.31.3.0-24'], ['tcp-443'], ''],
#                         ['OUTSIDE', 'INSIDE',['10.3.'], ['172.31.1.74'], '', ['ping']]]}
optitable_aos = {'fw-01': [['inside', 'outside', ['net-1-10.3.135.0-24'], ['r77ag-109557-1'], ['tcp-4020'], ''],
                      ['inside', 'outside', ['net-1-10.3.135.0-24'], ['srv-3-172.31.1.74'], '', ['ping']]]}
fw = Firewall(HOSTNAME, USERNAME, PASSWORD)
rulebase = Rulebase()
tmpl_name = rule_tmpl_prefix + "_" + rule_tmpl_name
tmpl_rule_1 = SecurityRule(tmpl_name)
rulebase.add(tmpl_rule_1)
fw.add(rulebase)
try:
    tmpl_rule_1.refresh()
except panos.errors.PanObjectMissing as e:
    print(f'Template {rule_tmpl_prefix}_{rule_tmpl_name} not found')
    exit()
i = 0
new_rules = []
tabela = regool.textui.Tabela()
#w tym skrypcie zakładamy konfigurację tylko jednego firewall'a
for dev in optitable_aos.keys():
    for r in optitable_aos[dev]:
        new_rule_params = copy_rule_params(tmpl_rule_1) #copy params from template
        new_rule_params['fromzone'] = r[0]
        new_rule_params['tozone'] = r[1]
        new_rule_params['source'] = r[2]
        new_rule_params['destination'] = r[3]
        new_rule_params['service'] = r[4] or 'application-default'
        new_rule_params['application'] = r[5] or 'any'
        i += 1
        # i służy do budowy nazw kolejnych reguł; zakładamy, że wszystkie reguły powstały w wyniki jednego wniosku (input_id)
        new_rule_params['name'] = rule_prefix + "_" + input_id + "_" + str(i)
        new_rules.append(new_rule_params)
        tabela.add_sr(dev, new_rule_params)
    tabela.print_sr()
    for params in new_rules:
        new_rule = SecurityRule(**params)
        rulebase.add(new_rule)
        try:
            new_rule.create()
            new_rule.move('after', tmpl_rule_1)
        except panos.errors.PanXapiError as e:
            print(f'Can not create security rule. Error message: {e}')
            exit(1)
fw.commit()       