"""Main loop for tester role"""

import logging

import helpers

def start(conf):
    """Main loop"""
    log = logging.getLogger(__name__)
    log.debug("Starting tester role with conf: \n%s\n", helpers.to_json(conf))
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
        log.warning("Empty monitor port, using %s", monitor_port_default)
        monitor_port = monitor_port_default

    log.debug("Getting config from %s:%s", monitor_host,
            monitor_port)
