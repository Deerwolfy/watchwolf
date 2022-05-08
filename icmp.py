import string
import random
import struct
import socket
import functools

ECHO_TYPE = 8
TIMESTAMP_TYPE = 13

class icmp_session:
  identifier = 0
  def __init__(self, icmp_type=ECHO_TYPE, destination='127.0.0.1', source='127.0.0.1'):
    self.destination = destination
    self.source = source
    self.icmp_type = icmp_type
    self.sequence = 0
    self.identifier = icmp_session.identifier
    icmp_session.identifier += 1
    self.data = ''.join(random.choices(string.ascii_letters, k=10))

    # Create raw socket
    self.socket = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_RAW)
    # Set option to indicate that IP header is included
    self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

  def create_echo(self):
    code = 0
    checksum = 0
    format_str = '!2B3H10s'
    icmp_size = struct.calcsize(format_str)
    icmp_packet = struct.pack(format_str, self.icmp_type, code, checksum, self.identifier, self.sequence,
        self.data.encode('ascii'))
    checksum = self.compute_checksum(icmp_packet)
    hex_checksum = hex(checksum)[2:]
    self.hex_packet = icmp_packet.hex()
    icmp_packet = bytes.fromhex(self.hex_packet[:4] + hex_checksum + self.hex_packet[8:])
    self.package = self.add_ip_headers(icmp_packet, icmp_size)
    
  def add_ip_headers(self, icmp_packet, icmp_size):
    version = 4
    length = 5
    dscp = 0
    ecn = 0
    total_length = icmp_size + length
    identification = 0
    flags = 0
    offset = 0
    ttl = 54
    checksum = 0
    protocol = 1
    source = functools.reduce(lambda a,b: (a << 8) + b, [int(x) for x in self.source.split('.')])
    destination = functools.reduce(lambda a,b: (a << 8) + b, [int(x) for x in self.destination.split('.')])
    format_str = '!2B3H2BH2I'
    ip_header = struct.pack(format_str, (version << 4) | length, (dscp << 2) | ecn, total_length,
        identification, (flags << 13) | offset, ttl, protocol, checksum, source, destination)
    checksum = self.compute_checksum(ip_header)
    hex_checksum = hex(checksum)[2:]
    hex_header = ip_header.hex()
    ip_header = bytes.fromhex(hex_header[:21] + hex_checksum + hex_header[25:])
    return ip_header + icmp_packet

  def compute_checksum(self, seq):
    even_length = len(seq)
    is_odd = len(seq) % 2
    if is_odd:
      even_length -= 1
    i = 0
    sixteens_sum = 0
    while i < even_length:
      most_seg_byte = seq[i]
      least_seg_byte = seq[i+1]
      sixteens_sum += (most_seg_byte << 8) + least_seg_byte
      i += 2
    # Handle last byte if odd
    if is_odd:
      sixteens_sum += seq[i]
    # Add carried ones to sum
    sixteens_sum = (sixteens_sum >> 16) + (sixteens_sum & 0xffff)
    # If another carry occur, add it again
    sixteens_sum += (sixteens_sum >> 16)
    # Invert and truncate hight order ones
    checksum = ~sixteens_sum & 0xffff
    return checksum

  def send_package(self):
    pass
  def parse_response(self):
    pass
