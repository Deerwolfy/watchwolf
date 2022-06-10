"""Main loop for tester role"""

import logging
import socket
import random
import string
import json
import types
import select
import time
import collections
import concurrent.futures
import urllib.request
import re

import helpers
import timer
import icmp

def connect_to_monitor(log, host, port):
    """Function to make connection to monitor"""
    log.debug("Connection to monitor %s:%s", host, port)
    mon_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mon_sock.settimeout(20)
    try:
        mon_sock.connect((host, port))
        log.info("Succsesfully connected to %s:%s", host, port)
    except TimeoutError:
        log.error("Connection to host %s timeouted", host)
        mon_sock.close()
        return None
    except ConnectionRefusedError:
        log.error("Connection refused by host %s", host)
        mon_sock.close()
        return None
    except ConnectionResetError:
        log.error("Connection reset by host %s", host)
        mon_sock.close()
        return None
    return mon_sock

def recieve_data(log, sock):
    """Recieve data from socket"""
    address = sock.getpeername()
    recieved_data = b""
    elapsed_timer = timer.Timer()
    elapsed_timer.start()
    timeout = 20
    log.debug("Waiting for response")
    while True:
        try:
            recieved_data += sock.recv(4096)
        except OSError:
            log.warning("Error reading response from %s", address)
        else:
            if not recieved_data:
                log.debug("Monitor %s closed connection", address)
                sock.close()
                return ""
            log.debug("Recieved data %s", recieved_data)
            if "\n".encode("ascii") in recieved_data:
                log.debug("Data is recieved")
                break
        log.debug("Elapsed time %s", elapsed_timer.time())
        if elapsed_timer.time() >= timeout:
            log.error("Request to monitor %s timeouted", address)
            sock.close()
            return ""
    return recieved_data.decode("ascii")


def get_config(log, name, host, port):
    """Get config string from monitor"""
    log.debug("Getting config from %s:%s", host, port)
    mon_sock = None
    wait_time = 0
    while not mon_sock:
        mon_sock = connect_to_monitor(log, host, port)
        if not mon_sock:
            if wait_time < 60:
                wait_time += 5
            log.error("Connection to monitor failed. retry in %s seconds",
                    wait_time)
            time.sleep(wait_time)
            continue
    data = f"NAME:{name}\nCONFIG_REQUEST:\n".encode("ascii")
    log.debug("Data to be send %s", data)
    mon_sock.sendall(data)
    log.debug("Data is sent")
    response = recieve_data(log, mon_sock)
    return (mon_sock, response)

def create_icmp(log, conf, name, source):
    """Create object for icmp target"""
    log.debug("Found %s with proto icmp", name)
    query_type = conf.get("type", "echo")
    log.debug("Choosen query type %s", query_type)
    try:
        destination = conf["dest"]
    except KeyError:
        log.error("Destination is not defined for %s. skipping", name)
        return None
    icmp_obj = types.SimpleNamespace(name=name, icmp=None)
    if query_type == "echo":
        icmp_obj.icmp = icmp.Echo(destination, source)
    elif query_type == "timestamp":
        icmp_obj.icmp = icmp.Timestamp(destination, source)
    else:
        log.error("Invalid icmp type %s in %s", query_type, name)
        return None
    log.debug("Created icmp %s", icmp_obj)
    return icmp_obj

def populate_objs(log, conf):
    """Create objects for targets"""
    source_ip = socket.gethostbyname(socket.gethostname())
    try:
        source_ip = conf["general"]["ip"]
    except KeyError:
        log.warning("Source ip is not defined, using %s", source_ip)
    icmp_objs = {}
    http = collections.namedtuple("HTTP", "name url regex")
    http_objs = [ ]
    for name, subconf in conf.items():
        if not name == "general":
            log.debug("Found %s with conf \n%s\n", name, subconf)
            try:
                proto = subconf["proto"]
            except KeyError:
                log.error("Proto field not found for %s def", name)
            else:
                if proto == "icmp":
                    obj = create_icmp(log, subconf, name, source_ip)
                    if obj:
                        icmp_objs[obj.icmp.get_scoket()] = obj
                elif proto in ("http", "https"):
                    log.debug("Found http %s", name)
                    try:
                        url = subconf["url"]
                    except KeyError:
                        log.error("No url for %s", name)
                        continue
                    try:
                        regex = subconf["regex"]
                    except KeyError:
                        log.error("No regex for %s", name)
                        continue
                    http_objs.append(http(name, url, regex))
    log.debug("Populated: %s %s", icmp_objs, http_objs)
    return icmp_objs, http_objs

def make_icmp(log, icmp_objs, timeout):
    """Make icmp requests and return results"""
    r_list = [ ]
    w_list = [ ]
    stats = {}
    elapsed_time = timer.Timer()
    for sock, val in icmp_objs.items():
        log.debug("Sending request to %s", val.name)
        val.icmp.send()
        r_list.append(sock)
    log.debug("All requests are sent")
    elapsed_time.start()
    while True:
        log.debug("Lists %s %s", r_list, w_list)
        read_ready, _, _ = select.select(r_list, w_list, [])
        for sock in read_ready:
            obj = icmp_objs[sock]
            log.debug("%s ready for read", obj.name)
            obj.icmp.recieve()
            if obj.icmp.is_response_ready():
                log.debug("%s response is read", obj.name)
                if obj.icmp.reply_good():
                    response = obj.icmp.get_response()
                    stats[obj.name] = response["time"]
                else:
                    stats[obj.name] = -1
                r_list.remove(sock)
        if not r_list:
            break
        if not read_ready and elapsed_time.time() > timeout:
            for sock in r_list:
                stats[icmp_objs[sock].name] = -1
            break
    return stats

def load_http(log, url, timeout):
    """Send http request and load response"""
    http_handler = urllib.request.HTTPHandler()
    https_handler = urllib.request.HTTPSHandler()
    opener = urllib.request.build_opener(http_handler, https_handler)
    with opener.open(url, timeout=timeout) as conn:
        log.debug("Sending HTTP request to %s", url)
        data = conn.read().decode('utf-8')
        #log.debug("Data for %s is \n%s\n", url, data)
        return data

def make_http(log, http_objs, timeout):
    """Make http requests to targets"""
    stats = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures_http = {executor.submit(
            load_http, log, http.url, timeout): http for http in http_objs}
        for future in concurrent.futures.as_completed(futures_http):
            http = futures_http[future]
            try:
                data = future.result()
            except urllib.error.URLError as err:
                log.error("Error loading %s, reason", http.url, err)
                stats[http.name] = False
            else:
                log.debug("Searching for %s", http.regex)
                if re.search(http.regex, data):
                    stats[http.name] = True
                else:
                    stats[http.name] = False
    return stats

def run_loop(log, conf, mon_host, mon_port, mon_sock):
    """Main tester loop"""
    icmp_objs, http_objs = populate_objs(log, conf)
    while True:
        stats = {}
        stats = stats | make_icmp(log, icmp_objs, 5)
        stats = stats | make_http(log, http_objs, 10)
        log.debug("Lap finished")
        log.debug("Stats: \n%s\n", helpers.to_json(stats))
        try:
            mon_sock.sendall(str("STATS_UPDATE:" +
                    json.dumps(stats) + "\n").encode("ascii"))
        except OSError:
            log.error("Cannot send stats to monitor, reconnecting")
            mon_sock = connect_to_monitor(log, mon_host, mon_port)
        time.sleep(5)

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
    conf = remote_conf | conf
    log.debug("Merged config: \n%s\n", helpers.to_json(conf))
    run_loop(log, conf, monitor_host, monitor_port, monitor_socket)
    if monitor_socket:
        monitor_socket.shutdown(socket.SHUT_RDWR)
        monitor_socket.close()
