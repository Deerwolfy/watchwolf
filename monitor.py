"""Main loop for monitor role"""

import logging
import socket
import json
import select
import types

import helpers

def recv_data(testers, log, sock):
    """Recieve data from tester"""
    address = sock.getpeername()
    recieved = b""
    try:
        recieved = sock.recv(4096)
    except OSError:
        log.warning("Error reading data from %s", address)
        return None
    log.debug("Recieved %s from %s", recieved, address)
    tester = testers[address]
    tester.recieved += recieved
    if "\n".encode("ascii") in tester.recieved:
        log.debug("Recieved complete message from host %s", address)
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
    return None

def process_request(log, requests, conf, tester):
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
            try:
                del conf["general"]
            except KeyError:
                log.info("General directive in remote conf not found")
            prepared_conf = str(conf).replace("\'", '"') + "\n"
            log.debug("Sending config to %s: \n%s\n", tester.address,
                    helpers.to_json(prepared_conf))
            tester.sock.sendall(prepared_conf.encode('ascii'))

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
                        recieved=b"",data_to_sent=b"",name="",
                        address=client.getpeername())
                r_list.append(client)
            else:
                messages = recv_data(testers, log, sock)
                if messages:
                    process_request(log, messages, conf,
                            testers[sock.getpeername()])

    for address, tester in testers:
        log.debug("Closing connection with %s", address)
        tester.sock.shutdown(socket.SHUT_RDWR)
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
