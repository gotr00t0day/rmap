
# RMap - Reconnaissance Mapper

![showcase](https://i.imgur.com/8t3Oe3r.png)

## Install

### PyPI

```
$ pip3 install python-rmap
```

### Git 

```
$ git clone https://github.com/syspuke/rmap.git
$ cd rmap
$ pip3 install -e .
```

## Usage

```
$ sudo rmap -h
usage: rmap [-h] [--vuln] [-d] [-v] ip

positional arguments:
  ip             Target IP Address

options:
  -h, --help     show this help message and exit
  --vuln         Scan host for vulnerabilities
  -d, --debug    Debug output
  -v, --version  Show version                           
```

```
$ sudo rmap 10.10.10.10
```

### Configuration

**/usr/share/rmap/rmap.conf**
```
[rmap]
# Max processes allowed to spawn
processLimit = 3

[nmap]
allports = true
arguments = -sC -sV

[ffuf]
wordlist = /usr/share/seclists/Discovery/Web-Content/big.txt

# Available formats: json, ejson, html, md, csv, ecsv
outtype = md

# Scan recursively
recursion = true
recursionDepth = 1

arguments = -fc 302
```