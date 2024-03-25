from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import AddressGroup
# Create config tree and refresh rules from live device
fw = Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys1")
rulebase = fw.add(Rulebase())
groups = fw.find("MyAG", AddressGroup)
groups.static_value
rules = SecurityRule.refreshall(rulebase)
rules.stati
aglist = fw.find('Foundation', AddressGroup)
for rule in rules:
    print(rule.name)