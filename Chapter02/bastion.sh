#!/bin/bash
# Bastion Host IPTables Script

# VARIABLES - Change these to match your environment.
# Location of the binaries
IPT="/sbin/iptables"
SYSCTL="/sbin/sysctl"

# Loopback Interface
LOOPBACK="lo"

# Define External Network
EXT_INTER="eth0"
EXT_ADDR="220.240.52.228"

# Define External Servers
EXT_NTP1="clock3.redhat.com"
EXT_NTP2="ntp.public.otago.ac.nz"

# Define Internal Network
INT_INTER="eth1"
INT_ADDR="192.168.0.100"
INT_NET="192.168.0.0/24"

# Define Internal Servers
INT_SMTP="192.168.0.20"
INT_DNS1="192.168.0.10"
INT_DNS2="192.168.0.11"

# Set Kernel Parameters
$SYSCTL -w net/ipv4/conf/all/accept_redirects="0"
$SYSCTL -w net/ipv4/conf/all/accept_source_route="0"
$SYSCTL -w net/ipv4/conf/all/log_martians="1"
$SYSCTL -w net/ipv4/conf/all/rp_filter="1"
$SYSCTL -w net/ipv4/icmp_echo_ignore_all="0"
$SYSCTL -w net/ipv4/icmp_echo_ignore_broadcasts="1"
$SYSCTL -w net/ipv4/icmp_ignore_bogus_error_responses="0"
$SYSCTL -w net/ipv4/ip_forward="0"
$SYSCTL -w net/ipv4/tcp_syncookies="1"

# Flush all Rules
$IPT -F

#Set Policies
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# Delete all User-created Chains
$IPT -X

# Allow access to the Loopback host
$IPT -A INPUT -i $LOOPBACK -j ACCEPT
$IPT -A OUTPUT -o $LOOPBACK -j ACCEPT

# Create ICMP Incoming Chain
$IPT -N ICMP_IN

# Pass ICMP Incoming Traffic to the ICMP Incoming Chain
$IPT -A INPUT -p icmp -j ICMP_IN

# Rules for ICMP Incoming Traffic
$IPT -A ICMP_IN -i $EXT_INTER -p icmp --icmp-type 0 -m state state ESTABLISHED,RELATED -j ACCEPT
$IPT -A ICMP_IN -i $EXT_INTER -p icmp --icmp-type 3 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A ICMP_IN -i $EXT_INTER -p icmp --icmp-type 11 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A ICMP_IN -i $EXT_INTER -p icmp -j LOG --log-prefix "IPT: ICMP_IN " $IPT -A ICMP_IN -i $EXT_INTER -p icmp -j DROP

# Create ICMP Outgoing Chain
$IPT -N ICMP_OUT

# Pass ICMP Outgoing Traffic to the ICMP Outgoing Chain
$IPT -A OUTPUT -p icmp -j ICMP_OUT

# Rules for ICMP Outgoing Traffic
$IPT -A ICMP_OUT -o $EXT_INTER -p icmp --icmp-type 8 -m state --state NEW -j ACCEPT
$IPT -A ICMP_OUT -o $EXT_INTER -p icmp -j LOG --log-prefix "IPT: ICMP_OUT "
$IPT -A ICMP_OUT -o $EXT_INTER -p icmp -j DROP 

# Create Bad Sources Chain
$IPT -N BAD_SOURCES

# Pass traffic with bad source addresses to the Bad Sources Chain
$IPT -A INPUT -j BAD_SOURCES

# Rules for traffic with bad source addresses
# Drop incoming traffic allegedly from our own host
$IPT -A BAD_SOURCES -i $INT_INTER -s $INT_ADDR -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s $EXT_ADDR -j DROP

# Drop outgoing traffic not from our own host
$IPT -A BAD_SOURCES -o $INT_INTER -s ! $INT_ADDR -j DROP
$IPT -A BAD_SOURCES -o $EXT_INTER -s ! $EXT_ADDR -j DROP

# Drop traffic from other bad sources
$IPT -A BAD_SOURCES -s 168.254.0.0/16 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 10.0.0.0/8 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 172.16.0.0/12 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 192.168.0.0/16 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 192.0.2.0/24 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 224.0.0.0/4 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 240.0.0.0/5 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 248.0.0.0/5 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 127.0.0.0/8 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 255.255.255.255/32 -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s 0.0.0.0/8 -j DROP

# Create Bad Flags Chain
$IPT -N BAD_FLAGS

# Pass traffic with bad flags to the Bad Flags Chain
$IPT -A INPUT -p tcp -j BAD_FLAGS

# Rules for traffic with bad flags
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix "IPT: Bad SF Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "IPT: Bad SR Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j LOG --log-prefix "IPT: Bad SFP Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j LOG --log-prefix "IPT: Bad SFR Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j LOG --log-prefix "IPT: Bad SFRP Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j LOG --log-prefix "IPT: Bad F Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "IPT: Null Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "IPT: All Flags "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j LOG --log-prefix "IPT: Nmap:Xmas Flags "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-prefix "IPT: Merry Xmas Flags "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Prevent SYN Flooding
$IPT -A INPUT -i $EXT_INTER -p tcp --syn -m limit --limit 5/second -j ACCEPT

# Log and Drop Traffic in the INVALID state
$IPT -A INPUT -m state --state INVALID -j LOG --log-prefix "IPT: INV_STATE "
$IPT -A INPUT -m state --state INVALID -j DROP

# Log and Drop Fragmented Traffic
$IPT -A INPUT -f -j LOG --log-prefix "IPT: Frag "
$IPT -A INPUT -f -j DROP

# Bastion Host Service Rules
# Internet SMTP Rules
$IPT -A INPUT -i $EXT_INTER -p tcp --dport smtp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p tcp --sport smtp -m state --state NEW,ESTABLISHED -j ACCEPT

# Internal Network SMTP Rules
$IPT -A INPUT -i $INT_INTER -p tcp -s $INT_SMTP --sport smtp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d $INT_SMTP --dport smtp -m state --state NEW,ESTABLISHED -j ACCEPT

# Internet DNS Rules
$IPT -A INPUT -i $EXT_INTER -p udp --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $EXT_INTER -p tcp --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p udp --sport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p tco --sport domain -m state --state NEW,ESTABLISHED -j ACCEPT


# Internal Network Incoming DNS Rules
$IPT -A INPUT -i $INT_INTER -p udp -s $INT_DNS1 --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INT_INTER -p udp -s $INT_DNS2 --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INT_INTER -p tcp -s $INT_DNS1 --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INT_INTER -p tcp -s $INT_DNS2 --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT

# Internal Network Outgoing DNS Rules
$IPT -A OUTPUT -o $INT_INTER -p udp -d $INT_DNS1 --sport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p udp -d $INT_DNS2 --sport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d $INT_DNS1 --sport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d $INT_DNS2 --sport domain -m state --state NEW,ESTABLISHED -j ACCEPT

# Internet NTP Rules
$IPT -A INPUT -i $EXT_INTER -p udp -s $EXT_NTP1 --dport ntp -m state --state ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $EXT_INTER -p udp -s $EXT_NTP2 --dport ntp -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p udp -d $EXT_NTP1 --sport ntp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p udp -d $EXT_NTP2 --sport ntp -m state --state NEW,ESTABLISHED -j ACCEPT

# Internal Network NTP Rules
$IPT -A INPUT -i $INT_INTER -p udp -s $INT_NET --dport ntp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p udp -d $INT_NET --sport ntp -m state --state ESTABLISHED -j ACCEPT

# Internal Network SSH Rules
$IPT -A INPUT -i $INT_INTER -p tcp -s $INT_NET --dport ssh -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d $INT_NET --sport ssh -m state --state ESTABLISHED -j ACCEPT

