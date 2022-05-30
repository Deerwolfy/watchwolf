"""Helper function for working with ip addresses"""
def check(ip):
    """Check if ip is correct"""
    octets = ip.split('.')
    if len(octets) == 4:
        for octet in (int(octet) for octet in octets):
            if octet < 0 or octet > 255:
                return False
        return True
    return False
