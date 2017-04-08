# Cyber Security Base - Course Project II
[https://cybersecuritybase.github.io](https://cybersecuritybase.github.io)

## Setup
* [Kali Linux](https://www.kali.org/)
* [Metasploitable 3](https://github.com/rapid7/metasploitable3) with its requirements
* [Snort](https://www.snort.org/) inside the Metasploitable
* [Metasploit Community](https://www.rapid7.com/products/metasploit/download/)

## Initial scan
Target ip in all cases: 172.28.128.3.

### Using Metasploit Community Web UI Scan tool
#### Results of the scan
| NAME         | PROTOCOL | PORT | INFO                                                  |
|--------------|----------|------|-------------------------------------------------------|
| ftp          | tcp      | 21   | 220 Microsoft FTP Service \x0d\x0a                    |
| ssh          | tcp      | 22   | SSH-2.0-OpenSSH_7.1                                   |
| http         | tcp      | 80   | Microsoft-IIS/7.5 (Powered by ASP:NET)                |
| appserv-http | tcp      | 4848 |                                                       |
| wap-wsp      | tcp      | 9200 |                                                       |
| snmp         | udp      | 161  | Hardware: Intel64 Family 6 Model 78 Stepping 3AT/...  |
| http         | tcp      | 8080 | Apache-Coyote/1.1                                     |
| http         | tcp      | 3000 | WEBrick/1.3.1 (Ruby/2.3.1/2016-04-26)                 |
| winrm        | tcp      | 5985 | Microsoft-HTTPAPI/2.0 Authentication Methods: ["Ne... |

### Using Metasploit Framework
Command: ´nmap -v -sV 172.28.128.3 -oA subnet_1´
#### Results
Nmap scan report for 172.28.128.3
Host is up (0.00064s latency).
Not shown: 990 filtered ports
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      Microsoft ftpd
22/tcp    open  ssh      OpenSSH 7.1 (protocol 2.0)
80/tcp    open  http     Microsoft IIS httpd 7.5
3000/tcp  open  http     WEBrick httpd 1.3.1 (Ruby 2.3.1 (2016-04-26))
4848/tcp  open  ssl/http Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
8022/tcp  open  http     Apache Tomcat/Coyote JSP engine 1.1
8080/tcp  open  http     Apache Tomcat/Coyote JSP engine 1.1
9200/tcp  open  http     Elasticsearch REST API 1.1.1 (name: Forbush Man; Lucene 4.7)
49153/tcp open  msrpc    Microsoft Windows RPC
49155/tcp open  msrpc    Microsoft Windows RPC
MAC Address: 08:00:27:E9:91:9E (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

## Three attacks that Snort identifies
### CVE-2015-1635
#### Commands in the msf
    use auxiliary/dos/http/ms15_034_ulonglongadd
    
### 2
### 3

## Two attacks that Snort doesn't identify
### 1
### 2

## Is it easier to fix the application than to detect attacks?