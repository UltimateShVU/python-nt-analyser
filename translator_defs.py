# definitions of signals
SIGINT  = 2

# definitions of ssh-ports
SSH_PORT = 22
SSH_PORT_ADDON = 2222

# definitions of http/https-ports
HTTP_PORT  = 80
HTTPS_PORT = 443

# FTP port
FTP_PORT = 21
FTP_PORT_ADDON = 20

# Telnet port
TELNET_PORT = 23

# TFTP port (by UDP)
TFTP_PORT = 69

# DNS port (by UDP)
DNS_PORT  = 53

# min. count of packets for ssh-connection
SSH_NEW_CONN_PCTS = 8

# enum for analyze.py module
ANALYZE_VERDICT_NORMAL  = 0
ANALYZE_VERDICT_INVALID = 1
ANALYZE_VERDICT_WARN    = 2

# DoS warning timers
MAX_PACK_PER_SECOND_IP  = 10
MAX_PACK_PER_SECOND_ALL = 100
