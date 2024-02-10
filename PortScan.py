import ipaddress
from scapy.layers.dns import *
from scapy.layers.inet import *

ports = [25,80,53,443,445,8080,8443]

def SynScan(host):
    print("\nSYN Scan Results:")
    ans,unans = sr(
        IP(dst=host)/
        TCP(sport=33333,dport=ports,flags="S")
        ,timeout=2,verbose=0)
    print("Open ports at %s:" % host)
    for (s,r) in ans:
        if s[TCP].dport == r[TCP].sport and r[TCP].flags=="SA":
            print(s[TCP].dport)
#Python for cybersecurity Chapter 1 Suggested Exercises #1
    print("Closed ports at %s:" % host)
    for (s,r) in ans:
        if s[TCP].dport == r[TCP].sport and r[TCP].flags=="RA":
            print(r[TCP].sport)
    print("Filtered ports at %s:" % host)
    for (s) in unans:
        print(s[TCP].dport)
    print()

#Suggested exercises #2
def AckScan(host):
    print("ACK Scan Results:")
    ans,unans = sr(
        IP(dst=host)/
        TCP(sport=33333,dport=ports,flags="A")
        ,timeout=2,verbose=0)
    print("Filtered ports at %s:" % host)
    for (r) in unans:
        print(r[TCP].dport)
    print("Unfiltered ports at %s:" % host)
    for (s,r) in ans:
        if s[TCP].dport == r[TCP].sport and r[TCP].flags=="RA":
            print(r[TCP].dport)
    print()

def XmasScan(host):
    print("XMAS Scan Results:")
    ans,unans = sr(
    IP(dst=host)/
    TCP(sport=33333,dport=ports,flags="FPU")
    ,timeout=2,verbose=0)
    print("Open|Filtered ports at %s:" % host)
    for (r) in unans:
        print(r[TCP].dport)
    print("Closed ports at %s:" % host)
    for (s,r) in ans:
        if s[TCP].dport==r[TCP].sport and r[TCP].flags=="":
            print(r[TCP].dport)
    print()

def DNSScan(host):
    print("DNS Scan Results:")
    ans,unans = sr(
        IP(dst=host)/
        UDP(dport=53)/
        DNS(rd=1,qd=DNSQR(qname="google.com"))
        ,timeout=2,verbose=0)
    if ans and ans[UDP]:
        print("DNS Server at %s"%host)
    print()
    
host = input("Enter IP Address: ")
try:
    ipaddress.ip_address(host)
except:
    print("Invalid address")
    exit(-1)

SynScan(host)
AckScan(host)
XmasScan(host)
DNSScan(host)
