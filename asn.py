import os

# Corrige variável HOME no Windows
if "HOME" not in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]

import ip2asn
import ipaddress

db = ip2asn.IP2ASN("./ip2asn-v4-u32.tsv")

result = db.lookup_address("8.8.8.8")

start = ipaddress.IPv4Address(result["ip_range"][0])
end = ipaddress.IPv4Address(result["ip_range"][1])

cidrs = list(ipaddress.summarize_address_range(start, end))

print(result)
print(cidrs)
# {'ip_text': '8.8.8.8', 'ip_numeric': 134744072, 'ip_range': [134744064, 134744319], 'ASN': '15169', 'country': 'US', 'owner': 'GOOGLE'}
# [IPv4Network('8.8.8.0/24')]