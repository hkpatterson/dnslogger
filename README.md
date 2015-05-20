# dnslogger
Send all DNS queries and responses to syslog

Listen to a network interface or read a pcap file and parse all the DNS
records. Send each DNS query and response to syslog in a "key=value" format.

KEYS
 type  :: Q  = Query (no corresponding response found within two seconds)
         QR = Query and response
         AR = Additional Response (when multiple answers are found to a query)
         R  = Response (no corresponding query found)
 cip   :: Client IP (Host making the DNS query)
 sip   :: Server IP (Host answering the DNS query)
 did   :: DNS ID (Useful for finding all responses of a query)
 q     :: Query
 qtype :: Query type (A, CNAME, PTR, AAAA, etc.)
 r     :: Response
 rtype :: Response type (A, CNAME, PTR, AAAA, etc.)
 qlen  :: Length of query
 rlen  :: Length of response

Requires:
 dpkt (apt-get install python-dpkt)
 pypcap (apt-get install python-pypcap)
 dnslib (https://bitbucket.org/paulc/dnslib/ :: pip install dnslib)

Typical usage:
dnslogger.py out.pcap

dnslogger.py eth0
