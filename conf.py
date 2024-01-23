import yaml
with open('config.yml') as file:
    try:
        Config = yaml.safe_load(file)
        print(Config)
    except yaml.YAMLError as exc:
        print(exc)
for r in Config['core']:
    print(r)
    #print(Config['core'][r]['type'])
    print(Config['core'])
for f in Config['firewalls']:
    print(f)
    print(Config['firewalls'][f]['type'])