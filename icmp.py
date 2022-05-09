import string
import random
import struct
import socket
import functools
import sys

BIG_ENDIAN = 0
LITTLE_ENDIAN = 1

class icmp_session:
  identifier = 0
  def __init__(self, destination='127.0.0.1', source='127.0.0.1'):
    self.destination = destination
    self.source = source
    self.icmp_type = 8
    self.sequence = 0
    self.identifier = icmp_session.identifier
    self.data_length = 10
    icmp_session.identifier += 1
    self.data = ''.join(random.choices(string.ascii_letters, k=self.data_length))
    self.clear_response_data()

    # Create raw socket
    self.socket = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # Set option to indicate that IP header is included
    self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

  def create_echo(self):
    """Create ICMP Echo request"""
    code = 0
    checksum = 0
    format_str = '2B3H{}s'.format(self.data_length)
    icmp_size = struct.calcsize(format_str)
    # Use big endian for packing
    icmp_packet = struct.pack('>' + format_str, self.icmp_type, code, checksum, self.identifier, self.sequence,
        self.data.encode('ascii'))
    checksum = self.compute_checksum(icmp_packet)
    # Repack package after checksum is known but in network byte order
    icmp_packet = struct.pack('!' + format_str, self.icmp_type, code, checksum, self.identifier, self.sequence,
        self.data.encode('ascii'))
    self.sequence += 1
    self.package = self.add_ip_headers(icmp_packet, icmp_size)
    self.to_be_sent = len(self.package)
    
  def add_ip_headers(self, icmp_packet, icmp_length):
    """Add IP Headers to a package"""
    version = 4
    length = 5
    dscp = 0
    ecn = 0
    total_length = icmp_length + length
    identification = 0
    flags = 0
    offset = 0
    ttl = 64
    checksum = 0
    protocol = 1
    source_octets = [int(x) for x in self.source.split('.')]
    source = functools.reduce(lambda a,b: (a << 8) + b, source_octets)
    destination_octets = [int(x) for x in self.destination.split('.')]
    destination = functools.reduce(lambda a,b: (a << 8) + b, destination_octets)
    version_and_length = (version << 4) | length
    dscp_and_ecn = (dscp << 2) | ecn
    flags_and_offset = (flags << 13) | offset
    format_str = '2B3H2BH2I'
    ip_header = struct.pack('>' + format_str, version_and_length, dscp_and_ecn, total_length,
        identification, flags_and_offset, ttl, protocol, checksum, source, destination)
    checksum = self.compute_checksum(ip_header)
    ip_header = struct.pack('!' + format_str, version_and_length, dscp_and_ecn, total_length,
        identification, flags_and_offset, ttl, protocol, checksum, source, destination)
    return ip_header + icmp_packet

  def compute_checksum(self, seq, endianess=BIG_ENDIAN):
    """Compute chesksum as 16-bit one's complement"""
    even_length = len(seq)
    is_odd = len(seq) % 2
    if is_odd:
      even_length -= 1
    i = 0
    sixteens_sum = 0
    while i < even_length:
      if endianess == BIG_ENDIAN:
        most_seg_byte = seq[i]
        least_seg_byte = seq[i+1]
      else:
        most_seg_byte = seq[i+1]
        least_seg_byte = seq[i]
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

  def clear_response_data(self):
    """Clear variables for new request"""
    self.recieved = 0
    self.response = b''
    self.response_length = 0
    self.parsed_response = {}
    self.response_ready = False

  def send_package(self):
    """Send next ICMP package"""
    self.create_echo()
    if self.to_be_sent:
      sent = self.socket.sendto(self.package,(self.destination, 0))
      self.to_be_sent -= sent
      self.package = self.package[sent:]
    else:
      # If whole request is sent than clear previous response
      self.clear_response_data()
    return self.recieve_response()

  def recieve_response(self):
    """Receive ICMP package"""
    response, address = self.socket.recvfrom(256)
    if address[0] == self.destination:
      self.recieved += len(response)
      self.response += response
      if self.recieved >= 4 and not self.response_length:
        total_length_raw = self.response[2:4]
        self.response_length = struct.unpack("!H", total_length_raw)[0]
      if self.response_length == self.recieved:
        self.parse_response()

  def parse_response(self):
    """Parse response and construct dictionary with values from response"""
    ip_header_raw = self.response[:20]
    icmp_packet_raw = self.response[20:]
    ip_header_format = '2B3H2BH2I'
    icmp_packet_format = '2B3H{}s'.format(self.data_length)
    ip_header = struct.unpack('!' + ip_header_format, ip_header_raw)
    icmp_packet = struct.unpack('!' + icmp_packet_format, icmp_packet_raw)
    ip = {
        'Version': (ip_header[0] >> 4) & 0x0f,
        'IHL': ip_header[0] & 0x0f,
        'DSCP': (ip_header[1] >> 2) & 63,
        'ECN': ip_header[1] & 3,
        'Total Length': ip_header[2],
        'Identification': ip_header[3],
        'Flags': (ip_header[4] >> 13) & 7,
        'Offset': ip_header[4] & ~(7 << 13),
        'TTL': ip_header[5],
        'Protocol': ip_header[6],
        'Checksum': ip_header[7],
        # Not sure about big byteorder
        'Source': socket.inet_ntoa(ip_header[8].to_bytes(4, byteorder='big')),
        'Destination': socket.inet_ntoa(ip_header[9].to_bytes(4, byteorder='big'))
        }
    icmp = {
        'Type': icmp_packet[0],
        'Code': icmp_packet[1],
        'Checksum': icmp_packet[2],
        'Identifier': icmp_packet[3],
        'Sequence': icmp_packet[4],
        'Data': icmp_packet[5]
        }
    self.parsed_response = {'ip': ip, 'icmp': icmp}
    self.response_ready = True

  def get_response(self):
    """Getter for response"""
    return self.parsed_response

  def process_event():
    """Event handler for select events"""
    pass
