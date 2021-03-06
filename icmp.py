"""Module for sending ICMP Echo and Timestamp requests"""
import string
import random
import struct
import socket
import functools
import datetime
import abc
import logging
import threading
import collections
from types import SimpleNamespace

from icmp_spec import type_codes
import timer
import ip
import helpers

BIG_ENDIAN = 0
LITTLE_ENDIAN = 1

log = logging.getLogger(__name__)

def sixteen_bit_complement(seq, endianess=BIG_ENDIAN):
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
    log.debug("Checksum: %s", checksum)
    return checksum

class ICMP(abc.ABC):
    """Abstract class for ICMP requests"""
    identifier = 0
    identifier_lock = threading.Lock()
    sec_before_timeout = 5
    IP_Header = collections.namedtuple("IP_Header",
            "format, length, version, ihl, dscp, ecn, identification, " +
            "flags, offset, ttl, protocol, destination, source")

    def __init__(self, destination, source):
        if not ip.check(destination):
            log.error("Invalid destination address")
            raise ValueError("Wrong destination ip format")
        if not ip.check(source):
            log.error("Invalid source address")
            raise ValueError("Wrong source ip format")

        self.icmp_packet = SimpleNamespace(format='2BH', sequence=0,
                identifier=type(self).identifier, code=0, type=0)
        with self.identifier_lock:
            type(self).identifier += 1
        self.ip_header = self.IP_Header('2B3H2BH2I',
                20, 4, 5, 0, 0, 0, 0, 0, 64, 1, destination, source)
        log.debug("IP headers:\n%s\n",
                helpers.to_json(self.ip_header._asdict()))
        self.elapsed_timer = timer.Timer()
        self.reply_icmp_type = 0
        self.request = None
        self.response = None
        self.clear_request_data()
        self.clear_response_data()
        # Create raw socket

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_ICMP)
        # Set option to indicate that IP header is included
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.socket.setblocking(False)

    def add_ip_headers(self, message):
        """Add IP Headers to a package"""
        total_length = len(message) + self.ip_header.length
        source_octets = [int(x)
                for x in self.ip_header.source.split('.')]
        source_byte = functools.reduce(
                lambda a, b: (a << 8) + b, source_octets)
        destination_octets = [int(x)
                for x in self.ip_header.destination.split('.')]
        destination_byte = functools.reduce(
                lambda a, b: (a << 8) + b, destination_octets)
        version_and_length = (self.ip_header.version << 4) | self.ip_header.ihl
        dscp_and_ecn = (self.ip_header.dscp << 2) | self.ip_header.ecn
        flags_and_offset = (self.ip_header.flags << 13) | self.ip_header.offset
        header = struct.pack('>' + self.ip_header.format,
                version_and_length, dscp_and_ecn, total_length,
                self.ip_header.identification, flags_and_offset,
                self.ip_header.ttl, self.ip_header.protocol,
                0, source_byte, destination_byte)
        checksum = sixteen_bit_complement(header)
        # Repack headers after computing checksum
        header = struct.pack('!' + self.ip_header.format,
                version_and_length, dscp_and_ecn, total_length,
                self.ip_header.identification, flags_and_offset,
                self.ip_header.ttl, self.ip_header.protocol,
                checksum, source_byte, destination_byte)
        log.debug("Packed IP headers: %s", header)
        return header + message

    def clear_response_data(self):
        """Clear variables from old response"""
        self.response = SimpleNamespace(raw=b'', parsed={}, is_ready=False,
                recieved=0, length=0)
        log.debug("Response data cleared")

    def clear_request_data(self):
        """Clear variables from old request"""
        self.request = SimpleNamespace(data='', to_be_sent=0)
        log.debug("Request data cleared")

    def send(self):
        """Send next ICMP package"""
        if not self.request.to_be_sent:
            self.create_package()
        self.elapsed_timer.start()
        if self.request.to_be_sent:
            try:
                sent = self.socket.sendto(self.request.data,
                        (self.ip_header.destination, 0))
                self.request.to_be_sent -= sent
                self.request.data = self.request.data[sent:]
                log.debug("Sent %s bytes, remaining %s bytes",
                        sent, self.request.to_be_sent)
            except OSError:
                log.warning("Error sending package")
                return
            if not self.request.to_be_sent:
                log.info("ICMP sent to %s", self.ip_header.destination)
                # If whole request is sent than clear previous response
                self.clear_response_data()

    def recieve(self):
        """Receive ICMP package"""
        try:
            response, _ = self.socket.recvfrom(256)
        except OSError:
            log.warning("Error while reading response")
            return
        self.response.recieved += len(response)
        self.response.raw += response
        log.debug("Recieved %s bytes", self.response.recieved)
        if self.response.recieved >= 4 and not self.response.length:
            total_length_raw = self.response.raw[2:4]
            try:
                self.response.length = struct.unpack("!H", total_length_raw)[0]
                log.debug("Expected response length: %s",
                        self.response.length)
            except struct.error:
                log.error("Error while parsing response length")
                self.abort()
                return
        if self.response.length == self.response.recieved:
            log.info("Package from %s recieved",
                    self.ip_header.destination)
            self.elapsed_timer.stop()
            self.parse_response(self.response.raw)

    def parse_ip_header(self, message):
        """Parse IP header of package"""
        ip_header_raw = message[:self.ip_header.length]
        try:
            unpacked_header = struct.unpack(f'!{self.ip_header.format}',
                    ip_header_raw)
            ip_parsed = {
                'Version': (unpacked_header[0] >> 4) & 0x0f,
                'IHL': unpacked_header[0] & 0x0f,
                'DSCP': (unpacked_header[1] >> 2) & 63,
                'ECN': unpacked_header[1] & 3,
                'Total Length': unpacked_header[2],
                'Identification': unpacked_header[3],
                'Flags': (unpacked_header[4] >> 13) & 7,
                'Offset': unpacked_header[4] & ~(7 << 13),
                'TTL': unpacked_header[5],
                'Protocol': unpacked_header[6],
                'Checksum': unpacked_header[7],
                # Not sure about big byteorder
                'Source': socket.inet_ntoa(unpacked_header[8]
                    .to_bytes(4, byteorder='big')),
                'Destination': socket.inet_ntoa(unpacked_header[9]
                    .to_bytes(4, byteorder='big'))
            }
        except struct.error:
            log.warning("Error while parsing ip header")
            ip_parsed = {}
        log.debug("Parsed response IP headers: \n%s\n",
                helpers.to_json(ip_parsed))
        return ip_parsed, message[self.ip_header.length:]

    def generic_parse(self, response):
        """Parser for general fields in ICMP package"""
        log.debug("Using generic parser")
        try:
            icmp_unpacked = struct.unpack('!2BH', response[:4])
            # If response type has codes
            if type_codes[icmp_unpacked[0]]['code']:
                # Get code by index
                code = type_codes[icmp_unpacked[0]]['code'][icmp_unpacked[1]]
            else:
                code = 0
            icmp_parsed = {
                'Type': icmp_unpacked[0],
                'Code': icmp_unpacked[1],
                'Checksum': icmp_unpacked[2],
                'Type Description': type_codes[icmp_unpacked[0]]['name'],
                'Code Description':  code
            }
        except (KeyError, IndexError, struct.error) as error:
            log.warning("Error while parsing ICMP: %s", error)
            icmp_parsed = {}
        log.debug("Parsed response icmp: \n%s\n", helpers.to_json(icmp_parsed))
        return icmp_parsed

    def get_response(self):
        """Getter for response"""
        return self.response.parsed

    def is_response_ready(self):
        """Getter for response readiness"""
        return self.response.is_ready

    def is_timeouted(self, timeout):
        """Check if elapsed time greater than passed timeout in seconds"""
        return self.elapsed_timer.time() >= timeout

    def get_elapsed_time(self):
        """Getter for elapsed time"""
        return self.elapsed_timer.time()

    def reply_good(self):
        """Check if reply contains good response type"""
        #try:
        return self.reply_icmp_type == self.response.parsed["icmp"]["Type"]
        #except KeyError:
        #    return False

    def get_scoket(self):
        """Socket getter"""
        return self.socket

    def do_lap(self):
        """Do one loop iteration"""
        if self.elapsed_timer.time() > self.sec_before_timeout:
            log.warning("Response waiting timeout")
            self.abort()
            raise TimeoutError(f"Host {self.ip_header.destination}")
        if self.request.to_be_sent:
            self.send()
        else:
            self.recieve()

    def abort(self):
        """Abort recieving and reset state"""
        # Clear all incoming data from socket
        log.debug("Abort")
        while True:
            try:
                self.socket.recv(4096)
            except OSError:
                log.debug("Receive buffer cleared")
                break
        self.clear_request_data()
        self.clear_response_data()

    @abc.abstractmethod
    def parse_response(self, response):
        """Parse recieved package"""
        raise NotImplementedError('Call to abstract method')

    @abc.abstractmethod
    def create_package(self):
        """Create package to send"""
        raise NotImplementedError('Call to abstract method')

class Echo(ICMP):
    """Class that represents Echo request"""
    def __init__(self, destination, source):
        super().__init__(destination, source)
        self.reply_icmp_type = 0
        self.data_length = 10
        self.data = ''.join(random.choices(string.ascii_letters,
            k=self.data_length))
        self.icmp_packet.format = f'2B3H{self.data_length}s'
        self.icmp_packet.type = 8
        self.icmp_packet.code = 0
        log.debug("ICMP headers: \n%s\n",
                helpers.to_json(vars(self.icmp_packet)))

    def create_package(self):
        """Create ICMP Echo request"""
        # Use big endian for packing
        icmp_packed = struct.pack('>' + self.icmp_packet.format,
                self.icmp_packet.type, self.icmp_packet.code,
                0, self.icmp_packet.identifier, self.icmp_packet.sequence,
                self.data.encode('ascii'))
        checksum = sixteen_bit_complement(icmp_packed)
        # Repack package after checksum is known but in network byte order
        icmp_packed = struct.pack('!' + self.icmp_packet.format,
                self.icmp_packet.type, self.icmp_packet.code,
                checksum, self.icmp_packet.identifier,
                self.icmp_packet.sequence, self.data.encode('ascii'))

        log.debug("Sending ICMP:%s %s %s %s %s", self.icmp_packet.type,
                self.icmp_packet.code, checksum, self.icmp_packet.identifier,
                self.icmp_packet.sequence)

        self.icmp_packet.sequence += 1
        log.debug("Packed icmp %s", icmp_packed)
        self.request.data = self.add_ip_headers(icmp_packed)
        self.request.to_be_sent = len(self.request.data)

    def parse_response(self, response):
        """Parse response and construct dictionary with values from response"""
        ip_parsed, icmp_packet_raw = self.parse_ip_header(response)
        if icmp_packet_raw:
            icmp_type_raw = bytes([icmp_packet_raw[0]])
            log.debug("Recieved ICMP type raw: %s", icmp_type_raw)
            try:
                icmp_type = struct.unpack("!B", icmp_type_raw)[0]
                if icmp_type != self.reply_icmp_type:
                    logging.warning("Wrong ICMP response type %s expected %s",
                            icmp_type, self.reply_icmp_type)
                    icmp_parsed = self.generic_parse(icmp_packet_raw)
                else:
                    icmp_unpacked = struct.unpack(
                            '!' + self.icmp_packet.format, icmp_packet_raw)
                    icmp_parsed = {
                        'Type': icmp_unpacked[0],
                        'Code': icmp_unpacked[1],
                        'Checksum': icmp_unpacked[2],
                        'Identifier': icmp_unpacked[3],
                        'Sequence': icmp_unpacked[4],
                        'Data': icmp_unpacked[5].decode('ascii')
                    }
            except struct.error as error:
                log.warning("Errow while parsing ICMP: %s", error)
                icmp_parsed = {}
        else:
            log.warning("Response is empty")
            icmp_parsed = {}
        self.response.parsed = {
                'ip': ip_parsed,
                'icmp': icmp_parsed,
                'time': self.elapsed_timer.time()
                }
        log.debug("Parsed response: \n%s\n",
                helpers.to_json(self.response.parsed))
        self.response.is_ready = True

class Timestamp(ICMP):
    """Class that represent Timestamp request"""
    def __init__(self, destination, source):
        super().__init__(destination, source)
        self.reply_icmp_type = 14
        self.icmp_packet.format = '2B3H3I'
        self.icmp_packet.type = 13
        self.icmp_packet.code = 0
        log.debug("ICMP headers: \n%s\n",
                helpers.to_json(vars(self.icmp_packet)))

    def create_package(self):
        """Create ICMP Echo request"""
        utc_timezone = datetime.timezone(datetime.timedelta())
        now = datetime.datetime.now(tz=utc_timezone)
        originate_timestamp = int((now - now.replace(hour=0, minute=0,
            second=0, microsecond=0)).total_seconds()*1000)
        # Use big endian for packing
        icmp_packed = struct.pack('>' + self.icmp_packet.format,
                self.icmp_packet.type, self.icmp_packet.code,
                0, self.icmp_packet.identifier, self.icmp_packet.sequence,
                originate_timestamp, 0, 0)
        checksum = sixteen_bit_complement(icmp_packed)
        # Repack package after checksum is known but in network byte order
        icmp_packed = struct.pack('!' + self.icmp_packet.format,
                self.icmp_packet.type, self.icmp_packet.code,
                checksum, self.icmp_packet.identifier,
                self.icmp_packet.sequence, originate_timestamp, 0, 0)

        self.icmp_packet.sequence += 1
        self.request.data = self.add_ip_headers(icmp_packed)
        self.request.to_be_sent = len(self.request.data)
        log.debug("Packed icmp %s", icmp_packed)

    def parse_response(self, response):
        """Parse response and construct dictionary with values from response"""
        ip_parsed, icmp_packet_raw = self.parse_ip_header(response)
        if icmp_packet_raw:
            icmp_type_raw = bytes([icmp_packet_raw[0]])
            try:
                icmp_type = struct.unpack("!B", icmp_type_raw)[0]
                if icmp_type != self.reply_icmp_type:
                    logging.warning("Wrong ICMP response type %s expected %s",
                            icmp_type, self.reply_icmp_type)
                    icmp_parsed = self.generic_parse(icmp_packet_raw)
                else:
                    icmp_unpacked = struct.unpack('!' + self.icmp_packet.format,
                            icmp_packet_raw)
                    icmp_parsed = {
                        'Type': icmp_unpacked[0],
                        'Code': icmp_unpacked[1],
                        'Checksum': icmp_unpacked[2],
                        'Identifier': icmp_unpacked[3],
                        'Sequence': icmp_unpacked[4],
                        'Originate Timestamp': icmp_unpacked[5],
                        'Receive Timestamp': icmp_unpacked[6],
                        'Transmit Timestamp': icmp_unpacked[7]
                    }
            except struct.error as error:
                log.warning("Error while parsing ICMP: %s", error)
                icmp_parsed = {}
        else:
            log.warning("Response is empty")
            icmp_parsed = {}
        self.response.parsed = {
                'ip': ip_parsed,
                'icmp': icmp_parsed,
                'time': self.elapsed_timer.time()}
        log.debug("Parsed response: \n%s\n",
                helpers.to_json(self.response.parsed))
        self.response.is_ready = True
