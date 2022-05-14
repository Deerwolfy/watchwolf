import icmp
import json

package = icmp.ICMP_Echo(destination="172.16.30.1", source="172.16.30.54")
package.send_package()
while not package.response_ready:
  package.process_event()
response = json.loads(str(package.get_response()).replace('\'','"'))
print(json.dumps(response,indent=2))
