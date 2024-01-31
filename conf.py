import yaml
with open('config.yml') as file:
    try:
        Config = yaml.safe_load(file)
        print(Config)
    except yaml.YAMLError as exc:
        print(exc)
# for r in Config['core']:
#     print(r)
#     print(Config['core'])
for f in Config['firewalls']:
    print(f)
    print(Config['firewalls'][f]['type'])
# for c in Config['convention']:
#     print(Config['convention'][c])
for cr in Config['route_source']:
    print(Config['route_source'][cr])
