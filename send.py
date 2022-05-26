import icmp
import json
import logging

localhost = '127.0.0.1'

dest = localhost
src = localhost

logging.basicConfig(level=logging.DEBUG)
package = icmp.ICMP_Timestamp(destination=dest, source=src)
package.send_package()
while not package.response_ready:
    package.process_event()
    response = json.loads(str(package.get_response()).replace('\'', '"'))
print(json.dumps(response, indent=2))
