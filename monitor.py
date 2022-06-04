"""Main loop for monitor role"""

import logging
import socket
import struct
import json
import select
import types

import helpers

def recv_data(testers, log, sock):
    """Recieve data from tester"""
    address = sock.getpeername()
    try:
        recieved = sock.recv(4096)
    except OSError:
        log.warning("Error reading data from %s", address)
        return None
    log.debug("Recieved %s from %s", recieved, address)
    tester = testers[address]
    tester.recieved += recieved
    total_length_recv = len(tester.recieved)
    if not tester.expected and total_length_recv >= 4:
        log.debug("Recieved >= 4 bytes from %s", address)
        raw_length = tester.recieved[:4]
        try:
            tester.expected = struct.unpack("!i", raw_length)[0]
        except struct.error:
            log.error("Error parsing data length from %s", address)
            tester.sock.shutdown(socket.SHUT_RDWR)
            tester.sock.close()
            log.debug("Connection closed with %s", address)
            return None
        log.debug("Size is %s", tester.expected)
        tester.recieved = tester.recieved[4:]

    if tester.recieved and tester.expected == len(tester.recieved):
        log.debug("Recieved all data from host %s", address)
        decoded = tester.recieved.decode('ascii')
        tester.recieved = b""
        tester.expected = 0
        return decoded
    return None

def testers_loop(server_socket, conf, log):
    """Main loop for connections from testers"""
    log.debug("Starting main loop")
    r_list = [ server_socket ]
    w_list = []
    testers = {}
    while True:
        log.debug("Select lists: %s %s", r_list, w_list)
        log.debug("Testers dict: \n%s\n", testers)
        ready_read, ready_write, _ = select.select(r_list, w_list, [])
        for sock in ready_read:
            if sock == server_socket:
                client, address = server_socket.accept()
                log.info("Accepting connection from %s", address)
                log.debug("Accepted peer name %s", client.getpeername())
                testers[address] = types.SimpleNamespace(sock=client,
                        recieved=b"",expected=0,sent=0,to_be_sent=0,
                        data_to_sent=b"")
                r_list.append(client)
            else:
                if recv_data(testers, log, sock):
                    pass

    for address, tester in testers:
        log.debug("Closing connection with %s", address)
        tester.sock.shutdown()
        tester.sock.close()

def start(conf):
    """Main loop"""
    log = logging.getLogger(__name__)
    log.debug("Starting monitor role with conf: \n%s\n", helpers.to_json(conf))
    ip_address = ""
    port = 5000
    try:
        ip_address = conf["general"]["ip"]
    except KeyError:
        log.info("No listening ip specified, listening on all interfaces")
    try:
        port = conf["general"]["port"]
    except KeyError:
        log.info("No port specified, using port %s", port)
    log.debug("Start listening on address %s:%s", ip_address, port)
    conf_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conf_socket.setblocking(False)
    conf_socket.bind((ip_address, port))
    conf_socket.listen()
    testers_loop(conf_socket, conf, log)
