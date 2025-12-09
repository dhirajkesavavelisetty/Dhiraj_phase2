Custom challenges - Digital Forensics


# 1. Hide and seek
Obtain flag from the image
## Solution:
- the clue was clear to use stegseek so i donwloaded stegseek and the rockyou word list from google and ran the command to obtain the flag
```
dhiraj@DESKTOP-361HESD:/mnt/c/Users/user/downloads$ tar -xzf rockyou.txt.tar.gz
dhiraj@DESKTOP-361HESD:/mnt/c/Users/user/downloads$ stegseek sakamoto.jpg rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "iloveyou1"
[i] Original filename: "flag.txt".
[i] Extracting to "sakamoto.jpg.out".

dhiraj@DESKTOP-361HESD:/mnt/c/Users/user/downloads$ cat sakamoto.jpg.out
nite{h1d3_4nd_s33k_but_w1th_st3g_sdfu9s8}
dhiraj@DESKTOP-361HESD:/mnt/c/Users/user/downloads$
```
## Flag:
```
nite{h1d3_4nd_s33k_but_w1th_st3g_sdfu9s8}
```
## Concepts learnt:
- leart how to use the stegseek tool
- learnt commands to install new commands and how to link the image and possword file to the command
## Resources:
-[About steganography](https://medium.com/@ria.banerjee005/steganography-tools-techniques-bba3f95c7148)
***


