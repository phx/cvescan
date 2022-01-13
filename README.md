# CVEscan

Dependencies:
- `/bin/sh`
- `nmap`
- `git`

This program makes sure you have all the pre-requisites ready to scan for CVEs using `nmap`.
Once the NSE scripts are in place, we do a full CVE scan using `nmap` under the hood, so all normal `nmap` options are available.

Since `vulners` is now a part of `nmap`, this script just makes sure that `vulscan` is also installed and the databases up-to-date
before running `nmap`.

Feel free to use and edit as necessary for your use-case. 

## Usage:

```
Usage: cvescan [options]

Options:
[no arguments - first run]	initial install/update of CVE databases and exit.

-h | --help			display this help text.
-u | --update			update CVE databases and exit.
-1 | --vulners [nmap arguments]	nmap scan using ONLY vulners NSE script.
-2 | --vulscan [nmap arguments] nmap scan using ONLY vulscan NSE script.
-3 | --all [nmap arguments]	nmap scan using BOTH vulners AND vulscan. (optional)

[nmap arguments]		Same as running with '-3' or '--all'.
				Default functionality is to use BOTH vulners AND vulscan.

The following additional arguments can be added when using '-2', '--vulscan', '-3', '--all',
(or default nmap arguments) in order to only use specific vulscan databases to return results:

--script-args vulscandb=cve.csv
--script-args vulscandb=exploitdb.csv
--script-args vulscandb=openvas.csv
--script-args vulscandb=osvdb.csv
--script-args vulscandb=scipvuldb.csv
--script-args vulscandb=securityfocus.csv
--script-args vulscandb=securitytracker.csv
--script-args vulscandb=xforce.csv
```

## Example Usage:

`git clone https://github.com/phx/cvescan && cd cvescan`

Put `cvescan` somewhere in your `$PATH` where you can summon it by name whenever you need it:

`sudo cp cvescan /usr/local/bin/`

First time usage:

`sudo cvescan`

Update the CVE databases:

`sudo cvescan -u`

Actually running a CVE scan:

`sudo cvescan google.com -p443`

(Yadda, yadda, will take all normal `nmap` arguments)

**Note:**

- requires `-sV`, and will add it automatically if it's not an existing argument.

## Example Output

```
MACC02ZQ8F3MD6X:cvescan phx$ sudo cvescan 127.0.0.1 -p22
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-13 09:37 CST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| vulscan: VulDB - https://vuldb.com:
| [170814] OpenSSH up to 8.4 ssh-agent double free
| [158983] OpenSSH up to 8.3p1 scp scp.c privilege escalation
| [157436] OpenSSH up to 8.3 Algorithm Negotiation information disclosure
| [155909] OpenSSH 8.2 scp Client privilege escalation
|
| MITRE CVE - https://cve.mitre.org:
| [CVE-2010-4755] The (1) remote_glob function in sftp-glob.c and the (2) process_put function in sftp.c in OpenSSH 5.8 and earlier, as used in FreeBSD 7.3 and 8.1, NetBSD 5.0.2, OpenBSD 4.7, and other products, allow remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in SSH_FXP_STAT requests to an sftp daemon, a different vulnerability than CVE-2010-2632.
| [CVE-1999-0661] A system is running a version of software that was replaced with a Trojan Horse at one of its distribution points, such as (1) TCP Wrappers 7.6, (2) util-linux 2.9g, (3) wuarchive ftpd (wuftpd) 2.2 and 2.1f, (4) IRC client (ircII) ircII 2.2.9, (5) OpenSSH 3.4p1, or (6) Sendmail 8.12.6.
| [CVE-2007-4654] Unspecified vulnerability in SSHield 1.6.1 with OpenSSH 3.0.2p1 on Cisco WebNS 8.20.0.1 on Cisco Content Services Switch (CSS) series 11000 devices allows remote attackers to cause a denial of service (connection slot exhaustion and device crash) via a series of large packets designed to exploit the SSH CRC32 attack detection overflow (CVE-2001-0144), possibly a related issue to CVE-2002-1024.
|
| SecurityFocus - https://www.securityfocus.com/bid/:
| [102780] OpenSSH CVE-2016-10708 Multiple Denial of Service Vulnerabilities
| [101552] OpenSSH 'sftp-server.c' Remote Security Bypass Vulnerability
| [94977] OpenSSH CVE-2016-10011 Local Information Disclosure Vulnerability
| [94975] OpenSSH CVE-2016-10012 Security Bypass Vulnerability
| [94972] OpenSSH CVE-2016-10010 Privilege Escalation Vulnerability
| [94968] OpenSSH CVE-2016-10009 Remote Code Execution Vulnerability
| [93776] OpenSSH 'ssh/kex.c' Denial of Service Vulnerability
| [92212] OpenSSH CVE-2016-6515 Denial of Service Vulnerability
| [92210] OpenSSH CBC Padding Weak Encryption Security Weakness
| [92209] OpenSSH MAC Verification Security Bypass Vulnerability
| [91812] OpenSSH CVE-2016-6210 User Enumeration Vulnerability
| [90440] OpenSSH CVE-2004-1653 Remote Security Vulnerability
| [90340] OpenSSH CVE-2004-2760 Remote Security Vulnerability
| [89385] OpenSSH CVE-2005-2666 Local Security Vulnerability
| [88655] OpenSSH CVE-2001-1382 Remote Security Vulnerability
| [88513] OpenSSH CVE-2000-0999 Remote Security Vulnerability
| [88367] OpenSSH CVE-1999-1010 Local Security Vulnerability
| [87789] OpenSSH CVE-2003-0682 Remote Security Vulnerability
| [86187] OpenSSH 'session.c' Local Security Bypass Vulnerability
| [86144] OpenSSH CVE-2007-2768 Remote Security Vulnerability
| [84427] OpenSSH CVE-2016-1908 Security Bypass Vulnerability
| [84314] OpenSSH CVE-2016-3115 Remote Command Injection Vulnerability
| [84185] OpenSSH CVE-2006-4925 Denial-Of-Service Vulnerability
| [81293] OpenSSH CVE-2016-1907 Denial of Service Vulnerability
| [80698] OpenSSH CVE-2016-0778 Heap Based Buffer Overflow Vulnerability
| [80695] OpenSSH CVE-2016-0777 Information Disclosure Vulnerability
| [76497] OpenSSH CVE-2015-6565 Local Security Bypass Vulnerability
| [76317] OpenSSH PAM Support Multiple Remote Code Execution Vulnerabilities
| [75990] OpenSSH Login Handling Security Bypass Weakness
| [75525] OpenSSH 'x11_open_helper()' Function Security Bypass Vulnerability
| [71420] Portable OpenSSH 'gss-serv-krb5.c' Security Bypass Vulnerability
| [68757] OpenSSH Multiple Remote Denial of Service Vulnerabilities
| [66459] OpenSSH Certificate Validation Security Bypass Vulnerability
| [66355] OpenSSH 'child_set_env()' Function Security Bypass Vulnerability
| [65674] OpenSSH 'ssh-keysign.c' Local Information Disclosure Vulnerability
| [65230] OpenSSH 'schnorr.c' Remote Memory Corruption Vulnerability
| [63605] OpenSSH 'sshd' Process Remote Memory Corruption Vulnerability
| [61286] OpenSSH Remote Denial of Service Vulnerability
| [58894] GSI-OpenSSH PAM_USER Security Bypass Vulnerability
| [58162] OpenSSH CVE-2010-5107 Denial of Service Vulnerability
| [54114] OpenSSH 'ssh_gssapi_parse_ename()' Function Denial of Service Vulnerability
| [51702] Debian openssh-server Forced Command Handling Information Disclosure Vulnerability
| [50416] Linux Kernel 'kdump' and 'mkdumprd' OpenSSH Integration Remote Information Disclosure Vulnerability
| [49473] OpenSSH Ciphersuite Specification Information Disclosure Weakness
| [48507] OpenSSH 'pam_thread()' Remote Buffer Overflow Vulnerability
| [47691] Portable OpenSSH 'ssh-keysign' Local Unauthorized Access Vulnerability
| [46155] OpenSSH Legacy Certificate Signing Information Disclosure Vulnerability
| [45304] OpenSSH J-PAKE Security Bypass Vulnerability
| [36552] Red Hat Enterprise Linux OpenSSH 'ChrootDirectory' Option Local Privilege Escalation Vulnerability
| [32319] OpenSSH CBC Mode Information Disclosure Vulnerability
| [30794] Red Hat OpenSSH Backdoor Vulnerability
| [30339] OpenSSH 'X11UseLocalhost' X11 Forwarding Session Hijacking Vulnerability
| [30276] Debian OpenSSH SELinux Privilege Escalation Vulnerability
| [28531] OpenSSH ForceCommand Command Execution Weakness
| [28444] OpenSSH X Connections Session Hijacking Vulnerability
| [26097] OpenSSH LINUX_AUDIT_RECORD_EVENT Remote Log Injection Weakness
| [25628] OpenSSH X11 Cookie Local Authentication Bypass Vulnerability
| [23601] OpenSSH S/Key Remote Information Disclosure Vulnerability
| [20956] OpenSSH Privilege Separation Key Signature Weakness
| [20418] OpenSSH-Portable Existing Password Remote Information Disclosure Weakness
| [20245] OpenSSH-Portable GSSAPI Authentication Abort Information Disclosure Weakness
| [20241] Portable OpenSSH GSSAPI Remote Code Execution Vulnerability
| [20216] OpenSSH Duplicated Block Remote Denial of Service Vulnerability
| [16892] OpenSSH Remote PAM Denial Of Service Vulnerability
| [14963] OpenSSH LoginGraceTime Remote Denial Of Service Vulnerability
| [14729] OpenSSH GSSAPI Credential Disclosure Vulnerability
| [14727] OpenSSH DynamicForward Inadvertent GatewayPorts Activation Vulnerability
| [11781] OpenSSH-portable PAM Authentication Remote Information Disclosure Vulnerability
| [9986] RCP, OpenSSH SCP Client File Corruption Vulnerability
| [9040] OpenSSH PAM Conversation Memory Scrubbing Weakness
| [8677] Multiple Portable OpenSSH PAM Vulnerabilities
| [8628] OpenSSH Buffer Mismanagement Vulnerabilities
| [7831] OpenSSH Reverse DNS Lookup Access Control Bypass Vulnerability
| [7482] OpenSSH Remote Root Authentication Timing Side-Channel Weakness
| [7467] OpenSSH-portable Enabled PAM Delay Information Disclosure Vulnerability
| [7343] OpenSSH Authentication Execution Path Timing Information Leakage Weakness
| [6168] OpenSSH Visible Password Vulnerability
| [5374] OpenSSH Trojan Horse Vulnerability
| [5093] OpenSSH Challenge-Response Buffer Overflow Vulnerabilities
| [4560] OpenSSH Kerberos 4 TGT/AFS Token Buffer Overflow Vulnerability
| [4241] OpenSSH Channel Code Off-By-One Vulnerability
| [3614] OpenSSH UseLogin Environment Variable Passing Vulnerability
| [3560] OpenSSH Kerberos Arbitrary Privilege Elevation Vulnerability
| [3369] OpenSSH Key Based Source IP Access Control Bypass Vulnerability
| [3345] OpenSSH SFTP Command Restriction Bypassing Vulnerability
| [2917] OpenSSH PAM Session Evasion Vulnerability
| [2825] OpenSSH Client X11 Forwarding Cookie Removal File Symbolic Link Vulnerability
| [2356] OpenSSH Private Key Authentication Check Vulnerability
| [1949] OpenSSH Client Unauthorized Remote Forwarding Vulnerability
| [1334] OpenSSH UseLogin Vulnerability
|
| IBM X-Force - https://exchange.xforce.ibmcloud.com:
| [83258] GSI-OpenSSH auth-pam.c security bypass
| [82781] OpenSSH time limit denial of service
| [82231] OpenSSH pam_ssh_agent_auth PAM code execution
| [74809] OpenSSH ssh_gssapi_parse_ename denial of service
| [72756] Debian openssh-server commands information disclosure
| [68339] OpenSSH pam_thread buffer overflow
| [67264] OpenSSH ssh-keysign unauthorized access
| [65910] OpenSSH remote_glob function denial of service
| [65163] OpenSSH certificate information disclosure
| [64387] OpenSSH J-PAKE security bypass
| [63337] Cisco Unified Videoconferencing OpenSSH weak security
| [46620] OpenSSH and multiple SSH Tectia products CBC mode information disclosure
| [45202] OpenSSH signal handler denial of service
| [44747] RHEL OpenSSH backdoor
| [44280] OpenSSH PermitRootLogin information disclosure
| [44279] OpenSSH sshd weak security
| [44037] OpenSSH sshd SELinux role unauthorized access
| [43940] OpenSSH X11 forwarding information disclosure
| [41549] OpenSSH ForceCommand directive security bypass
| [41438] OpenSSH sshd session hijacking
| [40897] OpenSSH known_hosts weak security
| [40587] OpenSSH username weak security
| [37371] OpenSSH username data manipulation
| [37118] RHSA update for OpenSSH privilege separation monitor authentication verification weakness not installed
| [37112] RHSA update for OpenSSH signal handler race condition not installed
| [37107] RHSA update for OpenSSH identical block denial of service not installed
| [36637] OpenSSH X11 cookie privilege escalation
| [35167] OpenSSH packet.c newkeys[mode] denial of service
| [34490] OpenSSH OPIE information disclosure
| [33794] OpenSSH ChallengeResponseAuthentication information disclosure
| [32975] Apple Mac OS X OpenSSH denial of service
| [32387] RHSA-2006:0738 updates for openssh not installed
| [32359] RHSA-2006:0697 updates for openssh not installed
| [32230] RHSA-2006:0298 updates for openssh not installed
| [32132] RHSA-2006:0044 updates for openssh not installed
| [30120] OpenSSH privilege separation monitor authentication verification weakness
| [29255] OpenSSH GSSAPI user enumeration
| [29254] OpenSSH signal handler race condition
| [29158] OpenSSH identical block denial of service
| [28147] Apple Mac OS X OpenSSH nonexistent user login denial of service
| [25116] OpenSSH OpenPAM denial of service
| [24305] OpenSSH SCP shell expansion command execution
| [22665] RHSA-2005:106 updates for openssh not installed
| [22117] OpenSSH GSSAPI allows elevated privileges
| [22115] OpenSSH GatewayPorts security bypass
| [20930] OpenSSH sshd.c LoginGraceTime denial of service
| [19441] Sun Solaris OpenSSH LDAP (1) client authentication denial of service
| [17213] OpenSSH allows port bouncing attacks
| [16323] OpenSSH scp file overwrite
| [13797] OpenSSH PAM information leak
| [13271] OpenSSH could allow an attacker to corrupt the PAM conversion stack
| [13264] OpenSSH PAM code could allow an attacker to gain access
| [13215] OpenSSH buffer management errors could allow an attacker to execute code
| [13214] OpenSSH memory vulnerabilities
| [13191] OpenSSH large packet buffer overflow
| [12196] OpenSSH could allow an attacker to bypass login restrictions
| [11970] OpenSSH could allow an attacker to obtain valid administrative account
| [11902] OpenSSH PAM support enabled information leak
| [9803] OpenSSH &quot
| [9763] OpenSSH downloaded from the OpenBSD FTP site or OpenBSD FTP mirror sites could contain a Trojan Horse
| [9307] OpenSSH is running on the system
| [9169] OpenSSH &quot
| [8896] OpenSSH Kerberos 4 TGT/AFS buffer overflow
| [8697] FreeBSD libutil in OpenSSH fails to drop privileges prior to using the login class capability database
| [8383] OpenSSH off-by-one error in channel code
| [7647] OpenSSH UseLogin option arbitrary code execution
| [7634] OpenSSH using sftp and restricted keypairs could allow an attacker to bypass restrictions
| [7598] OpenSSH with Kerberos allows attacker to gain elevated privileges
| [7179] OpenSSH source IP access control bypass
| [6757] OpenSSH &quot
| [6676] OpenSSH X11 forwarding symlink attack could allow deletion of arbitrary files
| [6084] OpenSSH 2.3.1 allows remote users to bypass authentication
| [5517] OpenSSH allows unauthorized access to resources
| [4646] OpenSSH UseLogin option allows remote users to execute commands as root
|
| Exploit-DB - https://www.exploit-db.com:
| [21579] OpenSSH 3.x Challenge-Response Buffer Overflow Vulnerabilities (2)
| [21578] OpenSSH 3.x Challenge-Response Buffer Overflow Vulnerabilities (1)
| [21402] OpenSSH 2.x/3.x Kerberos 4 TGT/AFS Token Buffer Overflow Vulnerability
| [21314] OpenSSH 2.x/3.0.1/3.0.2 Channel Code Off-By-One Vulnerability
| [20253] OpenSSH 1.2 scp File Create/Overwrite Vulnerability
| [17462] FreeBSD OpenSSH 3.5p1 - Remote Root Exploit
| [14866] Novell Netware 6.5 - OpenSSH Remote Stack Overflow
| [6094] Debian OpenSSH Remote SELinux Privilege Elevation Exploit (auth)
| [3303] Portable OpenSSH <= 3.6.1p-PAM / 4.1-SUSE Timing Attack Exploit
| [2444] OpenSSH <= 4.3 p1 (Duplicated Block) Remote Denial of Service Exploit
| [1572] Dropbear / OpenSSH Server (MAX_UNAUTH_CLIENTS) Denial of Service
| [258] glibc-2.2 and openssh-2.3.0p1 exploits glibc => 2.1.9x
| [26] OpenSSH/PAM <= 3.6.1p1 Remote Users Ident (gossh.sh)
| [25] OpenSSH/PAM <= 3.6.1p1 Remote Users Discovery Tool
|
| OpenVAS (Nessus) - http://www.openvas.org:
| [902488] OpenSSH 'sshd' GSSAPI Credential Disclosure Vulnerability
| [900179] OpenSSH CBC Mode Information Disclosure Vulnerability
| [881183] CentOS Update for openssh CESA-2012:0884 centos6
| [880802] CentOS Update for openssh CESA-2009:1287 centos5 i386
| [880746] CentOS Update for openssh CESA-2009:1470 centos5 i386
| [870763] RedHat Update for openssh RHSA-2012:0884-04
| [870129] RedHat Update for openssh RHSA-2008:0855-01
| [861813] Fedora Update for openssh FEDORA-2010-5429
| [861319] Fedora Update for openssh FEDORA-2007-395
| [861170] Fedora Update for openssh FEDORA-2007-394
| [861012] Fedora Update for openssh FEDORA-2007-715
| [840345] Ubuntu Update for openssh vulnerability USN-597-1
| [840300] Ubuntu Update for openssh update USN-612-5
| [840271] Ubuntu Update for openssh vulnerability USN-612-2
| [840268] Ubuntu Update for openssh update USN-612-7
| [840259] Ubuntu Update for openssh vulnerabilities USN-649-1
| [840214] Ubuntu Update for openssh vulnerability USN-566-1
| [831074] Mandriva Update for openssh MDVA-2010:162 (openssh)
| [830929] Mandriva Update for openssh MDVA-2010:090 (openssh)
| [830807] Mandriva Update for openssh MDVA-2010:026 (openssh)
| [830603] Mandriva Update for openssh MDVSA-2008:098 (openssh)
| [830523] Mandriva Update for openssh MDVSA-2008:078 (openssh)
| [830317] Mandriva Update for openssh-askpass-qt MDKA-2007:127 (openssh-askpass-qt)
| [830191] Mandriva Update for openssh MDKSA-2007:236 (openssh)
| [802407] OpenSSH 'sshd' Challenge Response Authentication Buffer Overflow Vulnerability
| [103503] openssh-server Forced Command Handling Information Disclosure Vulnerability
| [103247] OpenSSH Ciphersuite Specification Information Disclosure Weakness
| [103064] OpenSSH Legacy Certificate Signing Information Disclosure Vulnerability
| [100584] OpenSSH X Connections Session Hijacking Vulnerability
| [100153] OpenSSH CBC Mode Information Disclosure Vulnerability
| [66170] CentOS Security Advisory CESA-2009:1470 (openssh)
| [65987] SLES10: Security update for OpenSSH
| [65819] SLES10: Security update for OpenSSH
| [65514] SLES9: Security update for OpenSSH
| [65513] SLES9: Security update for OpenSSH
| [65334] SLES9: Security update for OpenSSH
| [65248] SLES9: Security update for OpenSSH
| [65218] SLES9: Security update for OpenSSH
| [65169] SLES9: Security update for openssh,openssh-askpass
| [65126] SLES9: Security update for OpenSSH
| [65019] SLES9: Security update for OpenSSH
| [65015] SLES9: Security update for OpenSSH
| [64931] CentOS Security Advisory CESA-2009:1287 (openssh)
| [61639] Debian Security Advisory DSA 1638-1 (openssh)
| [61030] Debian Security Advisory DSA 1576-2 (openssh)
| [61029] Debian Security Advisory DSA 1576-1 (openssh)
| [60840] FreeBSD Security Advisory (FreeBSD-SA-08:05.openssh.asc)
| [60803] Gentoo Security Advisory GLSA 200804-03 (openssh)
| [60667] Slackware Advisory SSA:2008-095-01 openssh
| [59014] Slackware Advisory SSA:2007-255-01 openssh
| [58741] Gentoo Security Advisory GLSA 200711-02 (openssh)
| [57919] Gentoo Security Advisory GLSA 200611-06 (openssh)
| [57895] Gentoo Security Advisory GLSA 200609-17 (openssh)
| [57585] Debian Security Advisory DSA 1212-1 (openssh (1:3.8.1p1-8.sarge.6))
| [57492] Slackware Advisory SSA:2006-272-02 openssh
| [57483] Debian Security Advisory DSA 1189-1 (openssh-krb5)
| [57476] FreeBSD Security Advisory (FreeBSD-SA-06:22.openssh.asc)
| [57470] FreeBSD Ports: openssh
| [56352] FreeBSD Security Advisory (FreeBSD-SA-06:09.openssh.asc)
| [56330] Gentoo Security Advisory GLSA 200602-11 (OpenSSH)
| [56294] Slackware Advisory SSA:2006-045-06 openssh
| [53964] Slackware Advisory SSA:2003-266-01 New OpenSSH packages
| [53885] Slackware Advisory SSA:2003-259-01 OpenSSH Security Advisory
| [53884] Slackware Advisory SSA:2003-260-01 OpenSSH updated again
| [53788] Debian Security Advisory DSA 025-1 (openssh)
| [52638] FreeBSD Security Advisory (FreeBSD-SA-03:15.openssh.asc)
| [52635] FreeBSD Security Advisory (FreeBSD-SA-03:12.openssh.asc)
| [11343] OpenSSH Client Unauthorized Remote Forwarding
| [10954] OpenSSH AFS/Kerberos ticket/token passing
| [10883] OpenSSH Channel Code Off by 1
| [10823] OpenSSH UseLogin Environment Variables
|
| SecurityTracker - https://www.securitytracker.com:
| [1028187] OpenSSH pam_ssh_agent_auth Module on Red Hat Enterprise Linux Lets Remote Users Execute Arbitrary Code
| [1026593] OpenSSH Lets Remote Authenticated Users Obtain Potentially Sensitive Information
| [1025739] OpenSSH on FreeBSD Has Buffer Overflow in pam_thread() That Lets Remote Users Execute Arbitrary Code
| [1025482] OpenSSH ssh-keysign Utility Lets Local Users Gain Elevated Privileges
| [1025028] OpenSSH Legacy Certificates May Disclose Stack Contents to Remote Users
| [1022967] OpenSSH on Red Hat Enterprise Linux Lets Remote Authenticated Users Gain Elevated Privileges
| [1021235] OpenSSH CBC Mode Error Handling May Let Certain Remote Users Obtain Plain Text in Certain Cases
| [1020891] OpenSSH on Debian Lets Remote Users Prevent Logins
| [1020730] OpenSSH for Red Hat Enterprise Linux Packages May Have Been Compromised
| [1020537] OpenSSH on HP-UX Lets Local Users Hijack X11 Sessions
| [1019733] OpenSSH Unsafe Default Configuration May Let Local Users Execute Arbitrary Commands
| [1019707] OpenSSH Lets Local Users Hijack Forwarded X Sessions in Certain Cases
| [1017756] Apple OpenSSH Key Generation Process Lets Remote Users Deny Service
| [1017183] OpenSSH Privilege Separation Monitor Validation Error May Cause the Monitor to Fail to Properly Control the Unprivileged Process
| [1016940] OpenSSH Race Condition in Signal Handler Lets Remote Users Deny Service and May Potentially Permit Code Execution
| [1016939] OpenSSH GSSAPI Authentication Abort Error Lets Remote Users Determine Valid Usernames
| [1016931] OpenSSH SSH v1 CRC Attack Detection Implementation Lets Remote Users Deny Service
| [1016672] OpenSSH on Mac OS X Lets Remote Users Deny Service
| [1015706] OpenSSH Interaction With OpenPAM Lets Remote Users Deny Service
| [1015540] OpenSSH scp Double Shell Character Expansion During Local-to-Local Copying May Let Local Users Gain Elevated Privileges in Certain Cases
| [1014845] OpenSSH May Unexpectedly Activate GatewayPorts and Also May Disclose GSSAPI Credentials in Certain Cases
| [1011193] OpenSSH scp Directory Traversal Flaw Lets Remote SSH Servers Overwrite Files in Certain Cases
| [1011143] OpenSSH Default Configuration May Be Unsafe When Used With Anonymous SSH Services
| [1007791] Portable OpenSSH PAM free() Bug May Let Remote Users Execute Root Code
| [1007716] OpenSSH buffer_append_space() and Other Buffer Management Errors May Let Remote Users Execute Arbitrary Code
| [1006926] OpenSSH Host Access Restrictions Can Be Bypassed By Remote Users
| [1006688] OpenSSH Timing Flaw With Pluggable Authentication Modules Can Disclose Valid User Account Names to Remote Users
| [1004818] OpenSSH's Secure Shell (SSH) Implementation Weakness May Disclose User Passwords to Remote Users During Man-in-the-Middle Attacks
| [1004616] OpenSSH Integer Overflow and Buffer Overflow May Allow Remote Users to Gain Root Access to the System
| [1004391] OpenSSH 'BSD_AUTH' Access Control Bug May Allow Unauthorized Remote Users to Authenticated to the System
| [1004115] OpenSSH Buffer Overflow in Kerberos Ticket and AFS Token Processing Lets Local Users Execute Arbitrary Code With Root Level Permissions
| [1003758] OpenSSH Off-by-one 'Channels' Bug May Let Authorized Remote Users Execute Arbitrary Code with Root Privileges
| [1002895] OpenSSH UseLogin Environment Variable Bug Lets Local Users Execute Commands and Gain Root Access
| [1002748] OpenSSH 3.0 Denial of Service Condition May Allow Remote Users to Crash the sshd Daemon and KerberosV Configuration Error May Allow Remote Users to Partially Authenticate When Authentication Should Not Be Permitted
| [1002734] OpenSSH's S/Key Implementation Information Disclosure Flaw Provides Remote Users With Information About Valid User Accounts
| [1002455] OpenSSH May Fail to Properly Restrict IP Addresses in Certain Configurations
| [1002432] OpenSSH's Sftp-server Subsystem Lets Authorized Remote Users with Restricted Keypairs Obtain Additional Access on the Server
| [1001683] OpenSSH Allows Authorized Users to Delete Other User Files Named Cookies
|
| OSVDB - http://www.osvdb.org:
| [92034] GSI-OpenSSH auth-pam.c Memory Management Authentication Bypass
| [90474] Red Hat / Fedora PAM Module for OpenSSH Incorrect error() Function Calling Local Privilege Escalation
| [90007] OpenSSH logingracetime / maxstartup Threshold Connection Saturation Remote DoS
| [81500] OpenSSH gss-serv.c ssh_gssapi_parse_ename Function Field Length Value Parsing Remote DoS
| [78706] OpenSSH auth-options.c sshd auth_parse_options Function authorized_keys Command Option Debug Message Information Disclosure
| [75753] OpenSSH PAM Module Aborted Conversation Local Information Disclosure
| [75249] OpenSSH sftp-glob.c remote_glob Function Glob Expression Parsing Remote DoS
| [75248] OpenSSH sftp.c process_put Function Glob Expression Parsing Remote DoS
| [72183] Portable OpenSSH ssh-keysign ssh-rand-helper Utility File Descriptor Leak Local Information Disclosure
| [70873] OpenSSH Legacy Certificates Stack Memory Disclosure
| [69658] OpenSSH J-PAKE Public Parameter Validation Shared Secret Authentication Bypass
| [67743] Novell NetWare OpenSSH SSHD.NLM Absolute Path Handling Remote Overflow
| [59353] OpenSSH sshd Local TCP Redirection Connection Masking Weakness
| [58495] OpenSSH sshd ChrootDirectory Feature SetUID Hard Link Local Privilege Escalation
| [56921] OpenSSH Unspecified Remote Compromise
| [53021] OpenSSH on ftp.openbsd.org Trojaned Distribution
| [50036] OpenSSH CBC Mode Chosen Ciphertext 32-bit Chunk Plaintext Context Disclosure
| [49386] OpenSSH sshd TCP Connection State Remote Account Enumeration
| [48791] OpenSSH on Debian sshd Crafted Username Arbitrary Remote SELinux Role Access
| [47635] OpenSSH Packages on Red Hat Enterprise Linux Compromised Distribution
| [47227] OpenSSH X11UseLocalhost X11 Forwarding Port Hijacking
| [45873] Cisco WebNS SSHield w/ OpenSSH Crafted Large Packet Remote DoS
| [43911] OpenSSH ~/.ssh/rc ForceCommand Bypass Arbitrary Command Execution
| [43745] OpenSSH X11 Forwarding Local Session Hijacking
| [43371] OpenSSH Trusted X11 Cookie Connection Policy Bypass
| [39214] OpenSSH linux_audit_record_event Crafted Username Audit Log Injection
| [37315] pam_usb OpenSSH Authentication Unspecified Issue
| [34850] OpenSSH on Mac OS X Key Generation Remote Connection DoS
| [34601] OPIE w/ OpenSSH Account Enumeration
| [34600] OpenSSH S/KEY Authentication Account Enumeration
| [32721] OpenSSH Username Password Complexity Account Enumeration
| [30232] OpenSSH Privilege Separation Monitor Weakness
| [29494] OpenSSH packet.c Invalid Protocol Sequence Remote DoS
| [29266] OpenSSH GSSAPI Authentication Abort Username Enumeration
| [29264] OpenSSH Signal Handler Pre-authentication Race Condition Code Execution
| [29152] OpenSSH Identical Block Packet DoS
| [27745] Apple Mac OS X OpenSSH Nonexistent Account Login Enumeration DoS
| [23797] OpenSSH with OpenPAM Connection Saturation Forked Process Saturation DoS
| [22692] OpenSSH scp Command Line Filename Processing Command Injection
| [20216] OpenSSH with KerberosV Remote Authentication Bypass
| [19142] OpenSSH Multiple X11 Channel Forwarding Leaks
| [19141] OpenSSH GSSAPIAuthentication Credential Escalation
| [18236] OpenSSH no pty Command Execution Local PAM Restriction Bypass
| [16567] OpenSSH Privilege Separation LoginGraceTime DoS
| [16039] Solaris 108994 Series Patch OpenSSH LDAP Client Authentication DoS
| [9562] OpenSSH Default Configuration Anon SSH Service Port Bounce Weakness
| [9550] OpenSSH scp Traversal Arbitrary File Overwrite
| [6601] OpenSSH *realloc() Unspecified Memory Errors
| [6245] OpenSSH SKEY/BSD_AUTH Challenge-Response Remote Overflow
| [6073] OpenSSH on FreeBSD libutil Arbitrary File Read
| [6072] OpenSSH PAM Conversation Function Stack Modification
| [6071] OpenSSH SSHv1 PAM Challenge-Response Authentication Privilege Escalation
| [5536] OpenSSH sftp-server Restricted Keypair Restriction Bypass
| [5408] OpenSSH echo simulation Information Disclosure
| [5113] OpenSSH NIS YP Netgroups Authentication Bypass
| [4536] OpenSSH Portable AIX linker Privilege Escalation
| [3938] OpenSSL and OpenSSH /dev/random Check Failure
| [3456] OpenSSH buffer_append_space() Heap Corruption
| [2557] OpenSSH Multiple Buffer Management Multiple Overflows
| [2140] OpenSSH w/ PAM Username Validity Timing Attack
| [2112] OpenSSH Reverse DNS Lookup Bypass
| [2109] OpenSSH sshd Root Login Timing Side-Channel Weakness
| [1853] OpenSSH Symbolic Link 'cookies' File Removal
| [839] OpenSSH PAMAuthenticationViaKbdInt Challenge-Response Remote Overflow
| [781] OpenSSH Kerberos TGT/AFS Token Passing Remote Overflow
| [730] OpenSSH Channel Code Off by One Remote Privilege Escalation
| [688] OpenSSH UseLogin Environment Variable Local Command Execution
| [642] OpenSSH Multiple Key Type ACL Bypass
| [504] OpenSSH SSHv2 Public Key Authentication Bypass
| [341] OpenSSH UseLogin Local Privilege Escalation
|_
| vulners:
|   cpe:/a:openbsd:openssh:8.1:
|     	CVE-2020-15778	6.8	https://vulners.com/cve/CVE-2020-15778
|     	C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	6.8	https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	*EXPLOIT*
|     	10213DBE-F683-58BB-B6D3-353173626207	6.8	https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207	*EXPLOIT*
|     	CVE-2021-41617	4.4	https://vulners.com/cve/CVE-2021-41617
|     	CVE-2019-16905	4.4	https://vulners.com/cve/CVE-2019-16905
|     	MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	*EXPLOIT*
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|_    	CVE-2016-20012	4.3	https://vulners.com/cve/CVE-2016-20012

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.24 seconds
```
