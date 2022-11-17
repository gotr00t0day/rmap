
# RMap - Reconnaissance Mapper

![showcase](https://i.imgur.com/7R0Wwpm.png)

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