"""Main loop for tester role"""

import logging
import socket
import random
import string
import struct
import json

import helpers

def get_config(log, name, host, port):
    """Get config string from monitor"""
    log.debug("Getting config from %s:%s", host,
            port)
    mon_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mon_sock.settimeout(20)
    try:
        mon_sock.connect((host, port))
        log.info("Succsesfully connected to %s:%s", host, port)
    except TimeoutError:
        log.error("Connection to host %s timeouted", host)
        mon_sock.close()
        return (None, {})
    except ConnectionRefusedError:
        log.error("Connection refused by host %s", host)
        mon_sock.close()
        return (None, {})
    data = f"NAME:{name}"
    raw_data = struct.pack(f"!i{len(data)}s", len(data), data.encode('ascii'))
    log.debug("Packed raw_data %s", raw_data)
    mon_sock.sendall(raw_data)
    log.debug("Data is sent")
    expected_length = 0
    recieved_data = b""
    while True:
        try:
            recieved_data += mon_sock.recv(4096)
        except OSError:
            log.warning("Error reading response from %s", host)
            continue
        log.debug("Recieved data %s", recieved_data)
        if not expected_length and len(recieved_data) >= 4:
            log.debug("Unpacking size")
            #Get first intenger that represents size
            raw_length = recieved_data[:4]
            try:
                expected_length = struct.unpack("!i", raw_length)[0]
            except struct.error:
                log.error("Error parsing response length from %s", host)
                mon_sock.shutdown(socket.SHUT_RDWR)
                mon_sock.close()
                log.debug("Connection closed with %s", host)
                return (None, {})
            log.debug("Size is %s", expected_length)
            recieved_data = recieved_data[4:]

        if recieved_data and expected_length == len(recieved_data):
            log.debug("Data is recieved")
            break
    try:
        unpacked_data = struct.unpack(f"!{expected_length}s", recieved_data)
    except struct.error:
        log.error("Error parsing response from %s", host)
        mon_sock.shutdown(socket.SHUT_RDWR)
        mon_sock.close()
        log.debug("Connection closed with %s", host)
        return (None, {})
    return (mon_sock, unpacked_data.decode("ascii"))

def start(conf):
    """Main loop"""
    log = logging.getLogger(__name__)
    log.debug("Starting tester role with conf: \n%s\n", helpers.to_json(conf))
    name = ''.join(random.choices(string.ascii_letters, k=8)).capitalize()
    try:
        name = conf["general"]["name"]
    except KeyError:
        log.warning("Name is not defined, using random name: %s", name)
    monitor_host_default = "localhost"
    monitor_port_default = 5000
    monitor_host = monitor_host_default
    monitor_port = monitor_port_default
    try:
        monitor_host, monitor_port = conf["general"]["monitor"].split(":")
    except KeyError:
        log.warning("Monitor not defined in General, using %s:%s",
                monitor_host_default, monitor_port_default)
    except ValueError:
        monitor_host = conf["general"]["monitor"]

    if not monitor_host:
        log.warning("Empty monitor host, using %s", monitor_host_default)
        monitor_host = monitor_host_default
    if not monitor_port:
        log.info("Empty monitor port, using %s", monitor_port_default)
        monitor_port = monitor_port_default

    monitor_socket, raw_conf = get_config(log, name, monitor_host,
            monitor_port)
    remote_conf = {}
    try:
        remote_conf = json.loads(raw_conf)
    except json.JSONDecodeError:
        log.error("Error parsing remote config, config: \n%s\n", raw_conf)
    conf = conf | remote_conf
    log.debug("Merged config: \n%s\n", helpers.to_json(conf))
    if monitor_socket:
        monitor_socket.shutdown()
        monitor_socket.close()
