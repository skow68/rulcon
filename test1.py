new_objects = {
    'server_1' : '192.168.10.1/32',
    'server_2' : '192.168.10.2/32',
    'server_3' : '192.168.10.3/32'
}
x = list(new_objects.keys())
print(x[0])
exit()
def is_none(thing):
    if thing is None:
        print("It's None")
    elif thing:
        print("It's True")
    else:
        print("It's False")
is_none()