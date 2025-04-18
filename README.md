# 

# /etc/sysctl.conf - Configuration file for setting system variables 

# See /etc/sysctl.d/ for additional system variables. 

# See sysctl.conf (5) for information. 

# 

 

#kernel.domainname = example.com 

 

# Uncomment the following to stop low-level messages on console 

#kernel.printk = 3 4 1 3 

 

##############################################################3 

# Functions previously found in netbase 

# 

 

# Uncomment the next two lines to enable Spoof protection (reverse-path filter) 

# Turn on Source Address Verification in all interfaces to 

# prevent some spoofing attacks 

#net.ipv4.conf.default.rp_filter=1 

#net.ipv4.conf.all.rp_filter=1 

 

# Uncomment the next line to enable TCP/IP SYN cookies 

# See http://lwn.net/Articles/277146/ 

# Note: This may impact IPv6 TCP sessions too 

#net.ipv4.tcp_syncookies=1 

 

# Uncomment the next line to enable packet forwarding for IPv4 

#net.ipv4.ip_forward=1 

 

# Uncomment the next line to enable packet forwarding for IPv6 

#  Enabling this option disables Stateless Address Autoconfiguration 

#  based on Router Advertisements for this host 

#net.ipv6.conf.all.forwarding=1 

 

 

################################################################### 

# Additional settings - these settings can improve the network 

# security of the host and prevent against some network attacks 

# including spoofing attacks and man in the middle attacks through 

# redirection. Some network environments, however, require that these 

# settings are disabled so review and enable them as needed. 

# 

# Do not accept ICMP redirects (prevent MITM attacks) 

#net.ipv4.conf.all.accept_redirects = 0 

#net.ipv6.conf.all.accept_redirects = 0 

# _or_ 

# Accept ICMP redirects only for gateways listed in our default 

# gateway list (enabled by default) 

# net.ipv4.conf.all.secure_redirects = 1 

# 

# Do not send ICMP redirects (we are not a router) 

#net.ipv4.conf.all.send_redirects = 0 

# 

# Do not accept IP source route packets (we are not a router) 

#net.ipv4.conf.all.accept_source_route = 0 

#net.ipv6.conf.all.accept_source_route = 0 

# 

# Log Martian Packets 

#net.ipv4.conf.all.log_martians = 1 

# 

 

################################################################### 

# Magic system request Key 

# 0=disable, 1=enable all 

# Debian kernels have this set to 0 (disable the key) 

# See https://www.kernel.org/doc/Documentation/sysrq.txt 

# for what other values do 

#kernel.sysrq=1 

 

################################################################### 

# Protected links 

# 

# Protects against creating or following links under certain conditions 

# Debian kernels have both set to 1 (restricted) 

# See https://www.kernel.org/doc/Documentation/sysctl/fs.txt 

#fs.protected_hardlinks=0 

#fs.protected_symlinks=0 

ubuntuadm@ETETax-EBXML1:~$ cat /etc/ssh/sshd_config 

#       $OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $ 

 

# This is the sshd server system-wide configuration file.  See 

# sshd_config(5) for more information. 

 

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin 

 

# The strategy used for options in the default sshd_config shipped with 

# OpenSSH is to specify options with their default value where 

# possible, but leave them commented.  Uncommented options override the 

# default value. 

 

#Port 22 

#AddressFamily any 

#ListenAddress 0.0.0.0 

#ListenAddress :: 

 

#HostKey /etc/ssh/ssh_host_rsa_key 

#HostKey /etc/ssh/ssh_host_ecdsa_key 

#HostKey /etc/ssh/ssh_host_ed25519_key 

 

# Ciphers and keying 

#RekeyLimit default none 

 

# Logging 

#SyslogFacility AUTH 

#LogLevel INFO 

 

# Authentication: 

 

#LoginGraceTime 2m 

#PermitRootLogin prohibit-password 

#StrictModes yes 

#MaxAuthTries 6 

#MaxSessions 10 

 

#PubkeyAuthentication yes 

 

# Expect .ssh/authorized_keys2 to be disregarded by default in future. 

#AuthorizedKeysFile     .ssh/authorized_keys .ssh/authorized_keys2 

 

#AuthorizedPrincipalsFile none 

 

#AuthorizedKeysCommand none 

#AuthorizedKeysCommandUser nobody 

 

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts 

#HostbasedAuthentication no 

# Change to yes if you don't trust ~/.ssh/known_hosts for 

# HostbasedAuthentication 

#IgnoreUserKnownHosts no 

# Don't read the user's ~/.rhosts and ~/.shosts files 

#IgnoreRhosts yes 

 

# To disable tunneled clear text passwords, change to no here! 

#PasswordAuthentication yes 

#PermitEmptyPasswords no 

 

# Change to yes to enable challenge-response passwords (beware issues with 

# some PAM modules and threads) 

ChallengeResponseAuthentication no 

 

# Kerberos options 

#KerberosAuthentication no 

#KerberosOrLocalPasswd yes 

#KerberosTicketCleanup yes 

#KerberosGetAFSToken no 

 

# GSSAPI options 

#GSSAPIAuthentication no 

#GSSAPICleanupCredentials yes 

#GSSAPIStrictAcceptorCheck yes 

#GSSAPIKeyExchange no 

 

# Set this to 'yes' to enable PAM authentication, account processing, 

# and session processing. If this is enabled, PAM authentication will 

# be allowed through the ChallengeResponseAuthentication and 

# PasswordAuthentication.  Depending on your PAM configuration, 

# PAM authentication via ChallengeResponseAuthentication may bypass 

# the setting of "PermitRootLogin without-password". 

# If you just want the PAM account and session checks to run without 

# PAM authentication, then enable this but set PasswordAuthentication 

# and ChallengeResponseAuthentication to 'no'. 

UsePAM yes 

 

#AllowAgentForwarding yes 

#AllowTcpForwarding yes 

#GatewayPorts no 

X11Forwarding yes 

#X11DisplayOffset 10 

#X11UseLocalhost yes 

#PermitTTY yes 

PrintMotd no 

#PrintLastLog yes 

#TCPKeepAlive yes 

#UseLogin no 

#PermitUserEnvironment no 

#Compression delayed 

#ClientAliveInterval 0 

#ClientAliveCountMax 3 

#UseDNS no 

#PidFile /var/run/sshd.pid 

#MaxStartups 10:30:100 

#PermitTunnel no 

#ChrootDirectory none 

#VersionAddendum none 

 

# no default banner path 

#Banner none 

 

# Allow client to pass locale environment variables 

AcceptEnv LANG LC_* 

 

# override default of no subsystems 

Subsystem       sftp    /usr/lib/openssh/sftp-server 

 

# Example of overriding settings on a per-user basis 

#Match User anoncvs 

#       X11Forwarding no 

#       AllowTcpForwarding no 

#       PermitTTY no 

#       ForceCommand cvs server 
