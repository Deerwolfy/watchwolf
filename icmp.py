import string
import random
import struct
import socket
import functools
import datetime
from abc import ABC, abstractmethod
from logger import Logger

import net_exception
import timer
import ip
from icmp_type import icmp_types

BIG_ENDIAN = 0
LITTLE_ENDIAN = 1


class ICMP(ABC):
    identifier = 0
    ip_header_format = '2B3H2BH2I'
    ip_header_length = 20
    sec_before_timeout = 5

    def __init__(self, destination, source):
        if not ip.check(destination):
            Logger.err("Invalid destination address")
            raise ValueError("Wrong destination ip format")
        if not ip.check(source):
            Logger.err("Invalid source address")
            raise ValueError("Wrong source ip format")
        self.destination = destination
        self.source = source
        self.sequence = 0
        self.identifier = ICMP.identifier
        ICMP.identifier += 1
        self.clear_response_data()
        self.request_timer = timer.Timer()

        # Create raw socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_ICMP)
        # Set option to indicate that IP header is included
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.socket.setblocking(False)

    def add_ip_headers(self, message):
        """Add IP Headers to a package"""
        version = 4
        length = 5
        dscp = 0
        ecn = 0
        total_length = len(message) + length
        identification = 0
        flags = 0
        offset = 0
        ttl = 64
        checksum = 0
        protocol = 1
        source_octets = [int(x) for x in self.source.split('.')]
        source = functools.reduce(lambda a, b: (a << 8) + b, source_octets)
        destination_octets = [int(x) for x in self.destination.split('.')]
        destination = functools.reduce(lambda a, b: (a << 8) + b, destination_octets)
        version_and_length = (version << 4) | length
        dscp_and_ecn = (dscp << 2) | ecn
        flags_and_offset = (flags << 13) | offset
        ip_header = struct.pack('>' + ICMP.ip_header_format, version_and_length, dscp_and_ecn, total_length,
                                identification, flags_and_offset, ttl, protocol, checksum, source, destination)
        checksum = self.compute_checksum(ip_header)
        ip_header = struct.pack('!' + ICMP.ip_header_format, version_and_length, dscp_and_ecn, total_length,
                                identification, flags_and_offset, ttl, protocol, checksum, source, destination)
        return ip_header + message

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
        self.create_package()
        self.request_timer.start()
        if self.to_be_sent:
            try:
                sent = self.socket.sendto(self.package, (self.destination, 0))
                self.to_be_sent -= sent
                self.package = self.package[sent:]
            except OSError:
                Logger.warn("Error sending package")
                return
            if not self.to_be_sent:
                Logger.info(f"ICMP sent to {self.destination}")
                # If whole request is sent than clear previous response
                self.clear_response_data()

    def recieve_response(self):
        """Receive ICMP package"""
        try:
            response, address = self.socket.recvfrom(256)
        except OSError:
            Logger.warn("Error while reading response")
            return
        self.recieved += len(response)
        self.response += response
        if self.recieved >= 4 and not self.response_length:
            total_length_raw = self.response[2:4]
            try:
                self.response_length = struct.unpack("!H", total_length_raw)[0]
            except struct.error:
                Logger.err("Error while parsing a package. Abort...")
                self.abort()
                return
        if self.response_length == self.recieved:
            Logger.info(f"Package from {self.destination} recieved")
            self.request_timer.stop()
            self.parse_response(self.response)

    def parse_IP_header(self, message):
        ip_header_raw = message[:ICMP.ip_header_length]
        try:
            ip_header = struct.unpack('!' + ICMP.ip_header_format, ip_header_raw)
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
        except struct.error:
            Logger.err("Error while parsing ip header")
            ip = {}
        return ip, message[ICMP.ip_header_length:]

    def generic_parse(self, response):
        try:
            icmp_packet = struct.unpack('!2BH', response[:4])
            # If response type has codes
            if icmp_types[icmp_packet[0]]['code']:
                # Get code by index
                code = icmp_types[icmp_packet[0]]['code'][icmp_packet[1]]
            else:
                code = 0
            icmp = {
                'Type': icmp_packet[0],
                'Code': icmp_packet[1],
                'Checksum': icmp_packet[2],
                'Type Description': icmp_types[icmp_packet[0]]['name'],
                'Code Description':  code
            }
        except (KeyError, IndexError, struct.error):
            Logger.err("Error while parsing ICMP")
            return {}
        return icmp

    def get_response(self):
        """Getter for response"""
        return self.parsed_response

    def process_event(self):
        """Event handler for select events"""
        if self.request_timer.time() > ICMP.sec_before_timeout:
            Logger.warn("Response waiting timeout")
            self.abort()
            raise net_exception.NetTimeoutException()
        if self.to_be_sent:
            self.send_package()
        else:
            self.recieve_response()

    def abort(self):
        # Clear all incoming data from socket
        while True:
            try:
                self.socket.recv(4096)
            except OSError:
                Logger.info("Receive buffer cleared")
                break
        self.to_be_sent = 0
        self.package = ''
        self.clear_response_data()

    @abstractmethod
    def parse_response(self, response):
        pass

    @abstractmethod
    def create_package(self):
        pass


class ICMP_Echo(ICMP):
    def __init__(self, destination, source):
        super().__init__(destination, source)
        self.icmp_type = 8
        self.reply_icmp_type = 0
        self.data_length = 10
        self.data = ''.join(random.choices(string.ascii_letters, k=self.data_length))
        self.icmp_format = '2B3H{}s'.format(self.data_length)

    def create_package(self):
        """Create ICMP Echo request"""
        code = 0
        checksum = 0
        # Use big endian for packing
        icmp_packet = struct.pack('>' + self.icmp_format, self.icmp_type, code, checksum, self.identifier, self.sequence,
                                  self.data.encode('ascii'))
        checksum = self.compute_checksum(icmp_packet)
        # Repack package after checksum is known but in network byte order
        icmp_packet = struct.pack('!' + self.icmp_format, self.icmp_type, code, checksum, self.identifier, self.sequence,
                                  self.data.encode('ascii'))
        self.sequence += 1
        self.package = self.add_ip_headers(icmp_packet)
        self.to_be_sent = len(self.package)

    def parse_response(self, response):
        """Parse response and construct dictionary with values from response"""
        ip, icmp_packet_raw = self.parse_IP_header(response)
        if icmp_packet_raw:
            icmp_type_raw = bytes([icmp_packet_raw[0]])
            try:
                icmp_type = struct.unpack("!B", icmp_type_raw)[0]
                if icmp_type != self.reply_icmp_type:
                    icmp = self.generic_parse(icmp_packet_raw)
                else:
                    icmp_packet = struct.unpack('!' + self.icmp_format, icmp_packet_raw)
                    icmp = {
                        'Type': icmp_packet[0],
                        'Code': icmp_packet[1],
                        'Checksum': icmp_packet[2],
                        'Identifier': icmp_packet[3],
                        'Sequence': icmp_packet[4],
                        'Data': icmp_packet[5].decode('ascii')
                    }
            except struct.error:
                Logger.err("Errow while parsing ICMP")
                icmp = {}
        else:
            Logger.err("Response is empty")
            icmp = {}
        self.parsed_response = {'ip': ip, 'icmp': icmp, 'time': self.request_timer.time()}
        self.response_ready = True


class ICMP_Timestamp(ICMP):
    def __init__(self, destination, source):
        super().__init__(destination, source)
        self.icmp_type = 13
        self.reply_icmp_type = 14
        self.icmp_format = '2B3H3I'

    def create_package(self):
        """Create ICMP Echo request"""
        code = 0
        checksum = 0
        utc_timezone = datetime.timezone(datetime.timedelta())
        now = datetime.datetime.now(tz=utc_timezone)
        originate_timestamp = int((now - now.replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds()*1000)
        # Use big endian for packing
        icmp_packet = struct.pack('>' + self.icmp_format, self.icmp_type, code, checksum, self.identifier, self.sequence,
                                  originate_timestamp, 0, 0)
        checksum = self.compute_checksum(icmp_packet)
        # Repack package after checksum is known but in network byte order
        icmp_packet = struct.pack('!' + self.icmp_format, self.icmp_type, code, checksum, self.identifier, self.sequence,
                                  originate_timestamp, 0, 0)
        self.sequence += 1
        self.package = self.add_ip_headers(icmp_packet)
        self.to_be_sent = len(self.package)

    def parse_response(self, response):
        """Parse response and construct dictionary with values from response"""
        ip, icmp_packet_raw = self.parse_IP_header(response)
        if icmp_packet_raw:
            icmp_type_raw = bytes([icmp_packet_raw[0]])
            try:
                icmp_type = struct.unpack("!B", icmp_type_raw)[0]
                if icmp_type != self.reply_icmp_type:
                    icmp = self.generic_parse(icmp_packet_raw)
                else:
                    icmp_packet = struct.unpack('!' + self.icmp_format, icmp_packet_raw)
                    icmp = {
                        'Type': icmp_packet[0],
                        'Code': icmp_packet[1],
                        'Checksum': icmp_packet[2],
                        'Identifier': icmp_packet[3],
                        'Sequence': icmp_packet[4],
                        'Originate Timestamp': icmp_packet[5],
                        'Receive Timestamp': icmp_packet[6],
                        'Transmit Timestamp': icmp_packet[7]
                    }
            except struct.error:
                Logger.err("Error while parsing ICMP")
                icmp = {}
        else:
            Logger.err("Response is empty")
            icmp = {}
        self.parsed_response = {'ip': ip, 'icmp': icmp, 'time': self.request_timer.time()}
        self.response_ready = True
