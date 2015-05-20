#!/usr/bin/python

# Written by Heath Patterson
# hpatterson@gmail.com

# This script will read packets from an interface or pcap file and log each
# DNS request and answer to syslog. All information is sent in a "key=value"
# format.

# KEYS
# type  :: Q  = Query (no corresponding response found within two seconds)
#         QR = Query and response
#         AR = Additional Response (when multiple answers are found to a query)
#         R  = Response (no corresponding query found)
# cip   :: Client IP (Host making the DNS query)
# sip   :: Server IP (Host answering the DNS query)
# did   :: DNS ID (Useful for finding all responses of a query)
# q     :: Query
# qtype :: Query type (A, CNAME, PTR, AAAA, etc.)
# r     :: Response
# rtype :: Response type (A, CNAME, PTR, AAAA, etc.)
# qlen  :: Length of query
# rlen  :: Length of response

# Requires the following:
#   dpkt (apt-get install python-dpkt)
#   pypcap (apt-get install python-pypcap)
#   dnslib (https://bitbucket.org/paulc/dnslib/ :: pip install dnslib)

# Current known limitations:
#   this program provides little to no error checking
#   only reads port 53
#   only works on UDP traffic

# Future improvements:
#   error handling
#   logging options
#   help screen
#   man page


import sys
import syslog
import dpkt
import pcap
import socket
from dnslib import *
from decimal import *

def extract(pkt):
# Extract the IP and DNS data from a packet
    ether = dpkt.ethernet.Ethernet(pkt)
    IP = ether.data
    L4 = IP.data
    DNS = DNSRecord.parse(L4.data)
    return(IP, DNS)

def addDB(i1, i2, tss, q, ts, key, ip, dns):
    while ts in i1:
        ts = ts + 3
    tss.append(ts)
    i1[ts] = key
    i2[key] = ts
    try:
        qtype = QTYPE[dns.q.qtype]
    except:
        qtype = 'UNK'
    q[key] = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst),
            str(dns.header.id), str(dns.q.qname), qtype, str(ip.p))

def log(q, ip, r, i1, i2, tss, ts, key):
    if q:
        cip = q[0]
        sip = q[1]
        did = q[2]
        try:
            rtype = QTYPE[r.a.rtype]
        except:
            rtype = "UNK"
        syslog.syslog('type=QR, cip=' + cip + ', sip=' + sip + ', did=' + did
            + ', qtype=' + q[4] + ', q=' + q[3] + ', r=' + str(r.a.rdata)
            + ', rtype=' + rtype + ', qlen=' + str(len(q[3])) + ', rlen='
            + str(len(str(r.a.rdata))))
        tss.remove(i2[key])
        i1.pop(i2.pop(key))
    else:
        cip = socket.inet_ntoa(ip.dst)
        sip = socket.inet_ntoa(ip.src)
        did = str(dns.header.id)
        try:
            rtype = QTYPE[dns.a.rtype]
        except:
            rtype = "UNK"
        syslog.syslog('type=R, cip=' + cip + ', sip=' + sip + ', did=' + did
            + ', q=' + str(dns.a.rname) + ', r=' + str(dns.a.rdata) + 'rtype='
            + rtype + ', qlen=' + str(len(str(dns.a.rname))) + ', rlen'
            + str(len(str(dns.a.rdata))))
    for i in r.rr[1:]: #Log any additional responses
        try:
            rtype = QTYPE[i.rtype]
        except:
            rtype = 'UNK'
        syslog.syslog('type=AR, cip=' + cip + ', sip=' + sip + ', did=' + did
            + ', q=' + str(i.rname) + ', r=' + str(i.rdata) + ', rtype=' + rtype
            + ', qlen=' + str(len(str(i.rname))) + ', rlen=' + str(len(str(i.rdata))))

def cleanup(ts, i1, i2, tss, q):
    while tss and (tss[0] < (ts - 2)):
        cts = tss.pop(0)
        key = i1.pop(cts)
        i2.pop(key)
        q1 = q.pop(key)
        syslog.syslog('type=Q, cip=' + q1[0] + ', sip=' + q1[1] + ', did='
                + q1[2] + ', qtype=' + q1[4] + ', q=' + q1[3] + ', qlen='
                + str(len(q1[3])))

def parse(p):
# The main worker function.

# Initialze our list and dictionaries. This will function as our database.
    index1 = {} # timestamp : key
    index2 = {} # key : timestamp
    tstamps = [] # list of timestamps
    q = {} # key : queries

# Start processing
    for ts, pkt in p:
        ts = Decimal(ts)
        success = True
        try:
            IP, DNS = extract(pkt)
        except:
            success = False
        if success: #If IP and DNS extraction was successful
            key = (int(IP.src.encode('hex'), 16) ^ int(IP.dst.encode('hex'),
                    16)) + DNS.header.id
            if not DNS.header.qr: #If packet was a query
                if key not in q: #check for duplicate query
                    addDB(index1, index2, tstamps, q, ts, key, IP, DNS)
            else: #If packet is repsonse
                if key in q: #If the corresponding request is in the database
                    log(q.pop(key), IP, DNS, index1, index2, tstamps, ts, key)
                else: #If the corresponding request is not in the database
                    log(0, IP, DNS, index1, index2, tstamps, ts, key)

        if tstamps:
            cleanup(ts, index1, index2, tstamps, q)

    if tstamps:
        cleanup(1, index1, index2, tstamps, q)

def main():
    source = pcap.pcap(sys.argv[1])
    source.setfilter('udp port 53')
    parse(source)

if __name__ == "__main__":
    main()
