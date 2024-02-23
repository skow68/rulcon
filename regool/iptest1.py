import re

#ip_with_optional_netmask_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\d{1,2})?$'
ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((?:/\d{1,2}))?$'
# Example usage:
ip_address = "10.10.143.0/24"

match = re.match(ip_pattern, ip_address)

if match:
    octets = match.group(1).split('.')  # Extract octets
    network_length = int(match.group(2)[1:]) if match.group(2) else None  # Extract network length
    # Check if octet values are in the range of 0-255 and network length is in the range of 0-32
    if all(0 <= int(octet) <= 255 for octet in octets) and (network_length is None or 0 <= network_length <= 32):
        print("Valid IP address with optional netmask")
    else:
        print("Invalid IP address with optional netmask")
else:
    print("Invalid IP address with optional netmask")
