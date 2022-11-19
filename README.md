
# RMap - Reconnaissance Mapper

![showcase](https://i.imgur.com/5TufzEU.png)

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
usage: rmap [-h] --ip IP [-d]

options:
  -h, --help  show this help message and exit
  --ip IP     IP Address
  -d          Debug output
```

```
$ sudo rmap --ip 10.10.10.10
```

### Configuration

**/usr/share/rmap/rmap.conf**
```
[rmap]
# Max processes allowed to spawn
processLimit = 3

[nmap]
allports = false
arguments = -sC -sV -O

[ffuf]
wordlist = /usr/share/seclists/Discovery/Web-Content/big.txt
# Available formats: json, ejson, html, md, csv, ecsv
outtype = md
```