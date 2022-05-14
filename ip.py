def check(ip):
  octets = ip.split('.')
  if len(octets) == 4:
    for octet in (int(octet) for octet in octets):
      if octet < 0 or octet > 255:
        return False
    else:
      return True
  return False
