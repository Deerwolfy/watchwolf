import json
import logging

import icmp

LOCALHOST = '127.0.0.1'

if __name__ == '__main__':
    dest = LOCALHOST
    src = LOCALHOST

    logging.basicConfig(level=logging.DEBUG)
    package = icmp.Echo(destination=dest, source=src)
    package.send_package()
    while not package.is_response_ready():
        package.process_event()
    response = json.loads(str(package.get_response()).replace('\'', '"'))
    print(json.dumps(response, indent=2))
