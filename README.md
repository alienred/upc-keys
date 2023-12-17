# upc-keys
WPA2 passphrase recovery tool for UPC%07d devices

## What is this?
[Novella/Meijer/Verdult](https://www.usenix.org/system/files/conference/woot15/woot15-paper-lorente.pdf) figured out that untouched WIFI access points by UPC are vulnerable to passphrase cracking attack based on their SSID. A [proof of concept](https://haxx.in/upc_keys.c) was quickly coded by [bl4sty](https://twitter.com/bl4sty). 

This python script based on [ProZsolt's key generator](https://github.com/ProZsolt/upc-keys) script written in ruby, for quickly generating dictionary for UPC WIFI access points. With added support for routers with serials starting with SAAP, SBAP and SAPP.

## Requirements
**Python**

## How to use

```
~$ python ./upc_keys.py UPC1234567
```
or redirect stdout into a file
```
$ python ./upc_keys.py UPC1234567 > UPC1234567.dict
```