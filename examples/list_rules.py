from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule

# Create config tree and refresh rules from live device
fw = Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys1")
rulebase = fw.add(Rulebase())
rules = SecurityRule.refreshall(rulebase)

for rule in rules:
    print(rule.name)