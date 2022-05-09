import icmp

package = icmp.icmp_session(destination="172.16.30.1", source="172.16.30.54")
package.send_package()
print(package.get_response())
