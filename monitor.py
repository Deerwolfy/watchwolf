"""Main loop for monitor role"""

import logging
import socket
import select
import types

import helpers

def recv_data(tester, log, sock):
    """Recieve data from tester"""
    recieved = b""
    try:
        recieved = sock.recv(4096)
    except OSError:
        log.warning("Error reading data from %s", tester.address)
        return None
    log.debug("Recieved %s from %s", recieved, tester.address)
    tester.recieved += recieved
    if "\n".encode("ascii") in tester.recieved:
        log.debug("Recieved complete message from host %s", tester.address)
        log.debug("Messages %s", tester.recieved)
        tester.recieved = tester.recieved.decode("ascii")
        last_completed = True
        if tester.recieved[-1] != "\n":
            log.debug("Last recieved message is incomplete")
            last_completed = False
        messages = tester.recieved.split("\n")
        if last_completed:
            tester.recieved = b""
        else:
            last = messages.pop()
            tester.recieved = last.encode('ascii')
        log.debug("Recieved messages %s", messages)
        return messages

    if not recieved:
        log.debug("Mark connection with %s to be closed", tester.address)
        tester.close = True
    return None

def process_request(log, requests, tester):
    """Process requests from testers"""
    while requests:
        request = requests.pop(0)
        log.debug("Processing request %s", request)
        request_name = ""
        request_value = ""
        try:
            request_name, request_value = request.split(":")
        except ValueError:
            log.error("Error parsing request from %s", tester.address)
            return
        if request_name == "NAME":
            tester.name = request_value
        elif request_name == "CONFIG_REQUEST":
            tester.config_requested = True

def accept_connection(log, server_socket):
    """Accept incoming connection from tester"""
    client, address = server_socket.accept()
    log.info("Accepting connection from %s", address)
    log.debug("Accepted peer name %s", client.getpeername())
    return types.SimpleNamespace(sock=client,
            recieved=b"",data_to_sent=b"",name="",
            address=client.getpeername(),close=False,
            config_requested=False)

def close_connections(log, testers):
    """Close all established connections"""
    for address, tester in testers:
        log.debug("Closing connection with %s", address)
        tester.sock.shutdown(socket.SHUT_RDWR)
        tester.sock.close()
    testers = {}

def process_read(log, sock, testers, r_list, w_list):
    """Process ready read"""
    try:
        address = sock.getpeername()
    except OSError:
        log.debug("Connection lost")
        r_list.remove(sock)
        return
    log.debug("Getting messages from %s", address)
    messages = recv_data(testers[address], log, sock)
    if messages:
        process_request(log, messages,
                testers[sock.getpeername()])
    if testers[address].config_requested:
        log.debug("Config request from %s", address)
        if not sock in w_list:
            w_list.append(sock)
    if testers[address].close:
        r_list.remove(sock)
        sock.close()
        del testers[address]
        log.debug("Connection with %s closed", address)

def process_write(log, sock, testers, w_list, prepared_conf):
    """Process ready write"""
    try:
        address = sock.getpeername()
    except OSError:
        log.debug("Connection lost")
        w_list.remove(sock)
        return
    if testers[address].config_requested:
        log.debug("Sending config to %s: \n%s\n", address,
                helpers.to_json(prepared_conf))
        testers[address].sock.sendall(prepared_conf.encode('ascii'))
        testers[address].config_requested = False
        w_list.remove(sock)

def testers_loop(server_socket, conf, log):
    """Main loop for connections from testers"""
    try:
        del conf["general"]
    except KeyError:
        log.info("General directive in remote conf not found")
    prepared_conf = str(conf).replace("\'", '"') + "\n"

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
                new_tester = accept_connection(log, server_socket)
                testers[new_tester.address] = new_tester
                r_list.append(new_tester.sock)
            else:
                process_read(log, sock, testers, r_list, w_list)

        for sock in ready_write:
            process_write(log, sock, testers, w_list, prepared_conf)

    close_connections(log, testers)

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
