#!/usr/bin/env python3
route_source = {
    "rt1": {
        "type": "Cisco",
        "name": 'rt1-001'
    },
    "rt2": {
        "type": "Cisco",
        "name": 'rt1-002'
    }
}
firewalls = {
    "fw1": {
        "type": "Palo",
        "name": "fw1-001",
        "vsys": "vsys1"
    },
    "fw2": {
        "type": "Palo",
        "name": "fw1-002",
        "vsys": "vsys1"
    }
}
route_to_outside ={
    '192.168.245.138': 'fw1',
    '192.168.245.139': 'fw2'
}
convention =  {
    'addr-group-pref': 'ag-',
    'sec-rule-pref': 'rule-'
}