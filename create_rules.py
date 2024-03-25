import sys
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressObject, AddressGroup
from panos.errors import PanObjectError
import inspect
HOSTNAME = "127.0.0.1"
USERNAME = "admin"
PASSWORD = "admin"
rule_tmpl_prefix = 'rt7744'
tmpl_name = 'first'
rule_params = ['source_user', 'hip_profiles', 'category', 'log_setting', 'log_start', 'log_end', 'type', 'tag', 'negate_source',
                'negate_destination', 'icmp_unreachable', 'disable_server_response_inspection', 'group', 'negate_target', 'target',
                  'virus', 'spyware', 'vulnerability', 'url_filtering', 'file_blocking', 'wildfire_analysis', 'data_filtering',
                    'group_tag']
def copy_rule_params(rule):
    new_rule = {}
    for p in rule_params:
        new_rule[p] = rule.p
def main():
    fw = Firewall(HOSTNAME, USERNAME, PASSWORD)
    rulebase = Rulebase()
    tmpl_rule_1 = SecurityRule(rule_tmpl_prefix + "_" + tmpl_name)
    rulebase.add(tmpl_rule_1)
    fw.add(rulebase)
    try:
        tmpl_rule_1.refresh()
    except PanObjectError as e:
        print(f'Template {rule_tmpl_prefix}_{tmpl_name} not found')
    tmpl_rule_1.action = 'allow'
    tmpl_rule_1.log_end = True

    #current_security_rules = SecurityRule.refreshall(rulebase)
if __name__ == "__main__":
    # This script doesn't take command line arguments.  If any are passed in,
    # then print out the script's docstring and exit.
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        # No CLI args, so run the main function.
        main()