# icmp-spoof
A simple ICMP spoofer that utilized raw socket and libpcap


## Dependency
```
apt install libpcap-dev
```

## Compile
```
gcc file.c -o file -lpcap
```

## Description
### icmpspoof.c
Spoof a ICMP packet to any IP <br />

### sns.c
Sniff any ICMP packet on network and spoof back to original sender <br />
