import ipaddress

def bytes2ip(bytestring):
    return str(ipaddress.IPv4Address(bytestring))