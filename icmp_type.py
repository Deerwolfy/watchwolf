icmp_types = [
    {'name': 'Echo Reply', 'codes': []},
    None,
    None,
    {'name': 'Destination Unreachable',
     'code': [
         'net unreachable',
         'host unreachable',
         'protocol unreachable',
         'port unreachable',
         'fragmentation needed and DF set',
         'source route failed'
     ]
     },
    {'name': 'Source Quench', 'code': []},
    {'name': 'Redirect',
     'code': [
         'Redirect datagrams for the Network',
         'Redirect datagrams for the Host',
         'Redirect datagrams for the Type of Service and Network',
         'Redirect datagrams for the Type of Service and Host'
     ]
     },
    None,
    None,
    {'name': 'Echo', 'code': []},
    None,
    None,
    {'name': 'Time Exceeded',
     'code': [
         'time to live exceeded in transit',
         'fragment reassembly time exceeded'
     ]
     },
    {'name': 'Parameter Problem', 'code': []},
    {'name': 'Timestamp', 'code': []},
    {'name': 'Timestamp Reply', 'code': []},
    {'name': 'Information Request', 'code': []},
    {'name': 'Information Reply', 'code': []}

]
