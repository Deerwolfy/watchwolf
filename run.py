"""Read config and start selected role"""
import logging
import sys

import conf_manager
import monitor
import tester

def main():
    """Do configuration, and launch main loop"""
    logging.basicConfig(
            format='%(levelname)s: %(asctime)s: %(name)s: %(message)s',
            level=logging.DEBUG,
            datefmt='%m-%d-%Y %I:%M:%S %p')
    log = logging.getLogger(__name__)

    if len(sys.argv) < 2:
        log.critical("Missing config path parameter")
        return

    config = conf_manager.parse(conf_manager.load(sys.argv[1]))

    try:
        role = config['general']['role']
    except KeyError:
        log.critical("Role is not defined. Abort.")
        return
    log.debug("My role is %s", role)

    if role == 'monitor':
        monitor.start(config)
    elif role == 'tester':
        tester.start(config)
    else:
        log.critical("Unknown role %s", role)

if __name__ == '__main__':
    main()
