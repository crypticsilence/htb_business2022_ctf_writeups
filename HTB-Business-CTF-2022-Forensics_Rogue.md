
# forensics_rogue

### Challenge Pretext: 
SecCorp has reached us about a recent cyber security incident. They are confident that a malicious entity has managed to access a shared folder that stores confidential files. Our threat intel informed us about an active dark web forum where disgruntled employees offer to give access to their employer's internal network for a financial reward. In this forum, one of SecCorp's employees offers to provide access to a low-privileged domain-joined user for 10K in cryptocurrency. Your task is to find out how they managed to gain access to the folder and what corporate secrets did they steal. 

This challenge consists a downloadable file only.  The zip file extracts to one Packet capture: `capture.pcapng`.

### Packet Capture
Browsed through the packet capture and found a few things.

Looked at the pcap, and investigated the tcp streams. The first transmission in the file is this connection on port 4444, looks like a reverse shell connection.  It includes some commands run in powershell:

![4444 cmds](https://github.com/crypticsilence/htb_business2022_ctf_writeups/blob/main/img/rogue-4444_1.png?raw=true)

Looks like the attacker determined the user is a local admin, then used comsvcs.dll to dump the LSASS security process, to hopefully get some password hashes off this computer.  Then the file is zipped up and sent across FTP to windowsliveupdater.net.  The filename is 3858793632.zip.

Was able to find the file upload sequence in the pcap :

![ftp login](https://github.com/crypticsilence/htb_business2022_ctf_writeups/blob/main/img/rogue-ftp_login.png?raw=true)

To see the upload data itself, filter for ftp-data : 

![ftp upload](https://github.com/crypticsilence/htb_business2022_ctf_writeups/blob/main/img/rogue-ftp_data.png?raw=true)

To save the file to disk, select them all, then use *File - Export Specified Packets - Save*.

### SMB
Further down in the capture, I see SMB3 connection to the corporate ConfidentialShare..

![confidential share](https://github.com/crypticsilence/htb_business2022_ctf_writeups/blob/main/img/rogue-smb_confidential_share.png?raw=true)

It is not easy to decrypt SMB3, as the key is not transmitted in the traffic, but I found a good article:

[Decrypting SMB Traffic with just a PCAP? Absolutely! Maybe..](https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2)

Per the article, this is what is needed to decrypt SMB3 traffic:
- User’s password or NTLM hash
- User’s domain
- User’s username
- NTProofStr
- Key Exchange Key (Also known as the NTLMv2 Session Base Key)
- Encrypted Session Key

In summary, the Random Session Key can be calculated by:

- Unicode (utf-16le) of password
- MD4 hash of the above (This is also the NTLM Hash of the password)
- Unicode(utf-16le) and Uppercase of Username and Domain/Workgroup together 
- Calculating the ResponseKeyNT via HMAC_MD5(NTLM Hash, Unicode of User/Domain above)
- NTProofStr (can be calculated but not needed as it is present in the PCAP)
- Calculating the KeyExchangeKey via HMAC_MD5(ResponseKeyNT,NTProofStr)
- Decrypt the Encrypted Session Key via RC4 and the Key Exchange Key to finally get the Random Session Key

### Pseudocode:
```
user= “test” 
domain= “workgroup”
password = “test”
NTProofStr = a0e42a75c54bbb0fab814593569faa22
EncryptedSessionKey = C914ADCEB0F1C32FB7C2548D8D959F01
hash = MD4(password.encode(‘utf16-le’))
# hash is 0cb6948805f797bf2a82807973b89537
ResponseKeyNT(HMAC_MD5(hash, (user.toUpper()+domain.toUpper()).encode(‘utf16-le’)))
# ResponseKeyNT is f31eb9f73fc9d5405f9ae516fb068315 
KeyExchangeKey=HMAC_MD5(ResponseKeyNT, NTProofStr)
# KeyExchangeKey is fd160d4ed7f2cb38f64262d7617f23b3
RandomSessionKey = RC4(KeyExchangeKey,EncryptedSessionKey)
# RandomSessionKey is 4462b99bb21423c29dbb4b4a983fde03
```

At first, I tried to figure out the credentials and authentication that was being used. I drilled down to the SecurityBlob and it looks to show data for NTLM, but it looks too long to be NTLM:

![securityblob](https://github.com/crypticsilence/htb_business2022_ctf_writeups/blob/main/img/rogue-pcap_ntlm.png?raw=true)

This must be NTLMv2.  The NTLM response and NTLMv2 response look to be the same length and value.

Since I really don't know much about this process, tried to dig a bit further and expand my knowledge on the topic.

The author mentioned MS Protocol Engineer Obaid Farooqi is where he learned this process.  Watched some of his @ MS Talk from 2015 (release of win10/svr2016) on SMB 3.1.1 decryption and took some notes:
[SMB 3.1.1 Encryption and Decryption (with MA) by Obaid Farooqi](https://www.youtube.com/watch?v=aGG7cpLxdfQ)

- Fixed cipher in 3.0x: AES-128-CCM. Not flexible
- Ciphers are neogitated per connection.  This allows to retire old ciphers and add new ones
- Client can require encryption even if server does not.
- New sniffers needed --Netmon new decryption etc
- Can use ETW tracing thru Message Analyzer - does not use decryption, so it is immune to cipher changes
- MA uses ETW tracing to capture traffic before it is encrypted and after it is decrypted for inbound

![computing hash value](https://i.imgur.com/XJbNpT4.png)

![deriving keys](https://i.imgur.com/f6d5euo.png)

From the PCAP, I gathered the following data:
```
Account: athomson
Domain: CORP
Host: WS02
DC=corp-dc.CORP.local
NTProofStr: d047ccdffaeafb22f222e15e719a34d4
NTLM Response: 01010000000000001d0d7416be8fd801cc28955a47693bb1000000000200080043004f005200500001000e0043004f00520050002d00440043000400140043004f00520050002e006c006f00630061006c000300240063006f00720070002d00640063002e0043004f00520050002e006c006f00630061006c000500140043004f00520050002e006c006f00630061006c00070008001d0d7416be8fd801060004000200000008003000300000000000000000000000002000009aa692c7c3da7b4e2469b58a15339dc8f3bd5d8679d0cd76ee0cdb333c6111380a001000000000000000000000000000000000000900180063006900660073002f0043004f00520050002d00440043000000000000000000
NTLMv2 Challenge: cc28955a47693bb1
NTLMv2 Response: 01010000000000001d0d7416be8fd801cc28955a47693bb1000000000200080043004f005200500001000e0043004f00520050002d00440043000400140043004f00520050002e006c006f00630061006c000300240063006f00720070002d00640063002e0043004f00520050002e006c006f00630061006c000500140043004f00520050002e006c006f00630061006c00070008001d0d7416be8fd801060004000200000008003000300000000000000000000000002000009aa692c7c3da7b4e2469b58a15339dc8f3bd5d8679d0cd76ee0cdb333c6111380a001000000000000000000000000000000000000900180063006900660073002f0043004f00520050002d00440043000000000000000000
```
Now, I know I need either the password to create the NTLM hash, or the NTLM hash itself.  The NTLM hash is much shorter than the NTLM Response above, so I know it is not correct.

Tried cracking the NTLMv2 hash first, but it is not working :
```
D:\download\hashcat\hashcat-5.1.0>hashcat64.exe --help | findstr /i ntlm
   5500 | NetNTLMv1                                        | Network Protocols
   5500 | NetNTLMv1+ESS                                    | Network Protocols
   5600 | NetNTLMv2                                        | Network Protocols
   1000 | NTLM                                             | Operating Systems

hashcat64.exe athomson.hash rockyou.txt -m 5600
Session..........: hashcat
Status...........: Exhausted
Hash.Type........: NetNTLMv2
```

From looking in the minidump with strings, I found a possible password : y0Secure%

This doesn't seem to be the actual athomson user password.  So, back to trying to crack the hash..  I was ultimately unsuccessful with Rockyou, best64.rule, using JTR and hashcat on a couple different machines.

So, the minidump seems like the obvious place to get a password.  However, the first time I extracted the ftp'd zip file from the PCAP, it showed it was a corrupt zip.  Tried to fix it with zip -FF and this worked to a point, but not good enough to actually use the minidump to get the hashes.. Later I was able to get a good zip and it extracted perfectly, but it was struggle street for a bit thinking I was supposed to be using this semi-corrupt zip file.  (In hindsight, it should have been obvious to re-save the file from the capture..)

Loaded it in Windbg, but I don't know how to browse the memory for passwords.  Loaded it up in mimikatz, but the file was corrupt and crashed mimikatz each time.  

I tried playing with it in a few different applications/scripts.  I tried out net-credz, pcredz, and BruteSharkCli on linux, and BruteShark and NetworkMiner on windows. Of course, none of them worked with the file I was using.

Played around a long time with trying to get volatility2 to work with the mimikatz.py plugin but my system already has volatility3 loaded .. In retrospect I should have just created a new user to get vol2 working, and just include ~/.local/bin in the path .. etc.. oh well, I am replacing my laptop soon, will install vol2 first then.  It wouldn't have worked with my corrupt file anyway..  Tried pypykatz as well, no luck.

Eventually extracted the FTP'd zip file again and found all my troubles went away as I had a good zip and good minidump file.  doh

Ended up just using pypykatz to dump all the hashes quickly on linux:
```
└──╼ #pypykatz lsa minidump 3858793632_1.pmd -k . -g > hashesWOOT.txt
┌─[root@parrotLT]─[/h/_ctf/business2022/forensics_rogue]
└──╼ #cat hashesWOOT.txt 
filename:packagename:domain:user:NT:LM:SHA1:masterkey:sha1_masterkey:key_guid:plaintext
3858793632_1.pmd:msv:WS02:rpaker:a9fdfa038c4b75ebc76dc855dd74f0da::9400ae28448e1364174dde269b2cce1bca9d7ee8::::
3858793632_1.pmd:msv:WS02:rpaker:a9fdfa038c4b75ebc76dc855dd74f0da::9400ae28448e1364174dde269b2cce1bca9d7ee8::::
3858793632_1.pmd:msv:WS02:rpaker:a9fdfa038c4b75ebc76dc855dd74f0da::9400ae28448e1364174dde269b2cce1bca9d7ee8::::
3858793632_1.pmd:msv:CORP:rpaker:a9fdfa038c4b75ebc76dc855dd74f0da::9400ae28448e1364174dde269b2cce1bca9d7ee8::::
3858793632_1.pmd:dpapi::::::e8d3cfbf9bc33a9fae8ec44bf0a1f2403d7d61e46ebb76f47765e99e2011997d0cca27c03cf4f3e57499be7bc9ed441ff3b4d40bf74863d06681fd17b59288cc:dd7ec586b58db250a64e2e15dec77d773690b916:ee05f40d-d31f-413c-b08c-98eb4da47687:
3858793632_1.pmd:msv:Window Manager:DWM-3:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:Window Manager:DWM-3:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:Font Driver Host:UMFD-3:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:CORP:athomson:88d84bad705f61fcdea0d771301c3a7d::60570041018a9e38fbee99a3e1f7bc18712018ba::::
3858793632_1.pmd:dpapi::::::00509f19c213842158ff61ac40bad16e395f7eaddc66d76e2c0e82d9803ee52bef5cd500e72ce5c261700b79832e3423ba117d88f8ae3eb71eb9c6216a3c223f:16f29541e8e3d010c0249048296c6b702a9bdc4d:a61d49d1-5c3a-4849-8880-738ce6f8027b:
3858793632_1.pmd:msv:CORP:athomson:88d84bad705f61fcdea0d771301c3a7d::60570041018a9e38fbee99a3e1f7bc18712018ba::::
3858793632_1.pmd:msv:Window Manager:DWM-2:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:Window Manager:DWM-2:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:Font Driver Host:UMFD-2:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:WS02:rpaker:a9fdfa038c4b75ebc76dc855dd74f0da::9400ae28448e1364174dde269b2cce1bca9d7ee8::::
3858793632_1.pmd:msv:WS02:rpaker:a9fdfa038c4b75ebc76dc855dd74f0da::9400ae28448e1364174dde269b2cce1bca9d7ee8::::
3858793632_1.pmd:msv:Window Manager:DWM-1:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:Window Manager:DWM-1:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:CORP:WS02$:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:msv:Font Driver Host:UMFD-0:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:Font Driver Host:UMFD-1:d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:kerberos:CORP.local:WS02$:::::::+8=YyKd=]>'c+?3U`!E_a;lwr'Lk:r>>HQM_<9/Q;3bpR_65lw>TBB1sIgo=+Pp$E"<?myROL!;dA!;x`_ix\N!%QE@po;ayP'eB9Cn['=g/Iah.m"o<98VJ
3858793632_1.pmd:msv:::d22d6b1d22e752ede3fcc8a4f19f0996::4c5e4099919d65ecfe221bab4f385df3d3d53fa8::::
3858793632_1.pmd:dpapi::::::fa1368d332e39fe5eb07d3a1600453e9f19170923369b104bc41cdef92dc469ff5bc39936d916f426273baa1ad9d86233d81fbb0864e343ca1f47811871c0e32:99c3409540732948afaedd1b6d7e7528c97978e9:094fa06d-8eae-4f0f-864a-009e98d06f6c:
```
That was quite a sigh of relief. Burned a couple hours on playing around with a bad file.  I am not smart sometimes.
Also, it created some .kirbi files for me, kerberos tickets.

But, finally got what I needed, ntlm-style:

`CORP:athomson:88d84bad705f61fcdea0d771301c3a7d::60570041018a9e38fbee99a3e1f7bc18712018ba::::`

I think the ntlm hash is 60570041018a9e38fbee99a3e1f7bc18712018ba
But, wrong again.  It's the shorter one:
```
└──╼ #hashid 60570041018a9e38fbee99a3e1f7bc18712018ba
Analyzing '60570041018a9e38fbee99a3e1f7bc18712018ba'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160) 

┌─[root@parrotLT]─[/h/_ctf/business2022/forensics_rogue]
└──╼ #hashid 88d84bad705f61fcdea0d771301c3a7d
Analyzing '88d84bad705f61fcdea0d771301c3a7d'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x 
```
Can't crack it though.. Tried john, hashcat and online cracking.  Although, we probably don't need to..

Time to re-test my assumptions of having the correct hash.  Tried a full output from pypykatz just in case, saved to pypykatz_fulldump.txt:
```
[..]
== LogonSession ==
authentication_id 3857660 (3adcfc)
session_id 2
username athomson
domainname CORP
logon_server CORP-DC
logon_time 2022-07-04T11:32:10.805162+00:00
sid S-1-5-21-288640240-4143160774-4193478011-1110
luid 3857660
        == MSV ==
                Username: athomson
                Domain: CORP
                LM: NA
                NT: 88d84bad705f61fcdea0d771301c3a7d
                SHA1: 60570041018a9e38fbee99a3e1f7bc18712018ba
                DPAPI: 022e4b6c4a40b4343b8371abbfa9a1a0
        == WDIGEST [3adcfc]==
                username athomson
                domainname CORP
                password None
                password (hex)
        == Kerberos ==
                Username: athomson
                Domain: CORP.LOCAL
        == WDIGEST [3adcfc]==
                username athomson
                domainname CORP
                password None
                password (hex)
        == DPAPI [3adcfc]==
                luid 3857660
                key_guid a61d49d1-5c3a-4849-8880-738ce6f8027b
                masterkey 00509f19c213842158ff61ac40bad16e395f7eaddc66d76e2c0e82d9803ee52bef5cd500e72ce5c261700b79832e3423ba117d88f8ae3eb71eb9c6216a3c:
[..]
```
Good deal.  So now I have the stuff I need I think finally to build the smb3 key:

In recap of the article, the Random Session Key can be calculated by:

- Unicode (utf-16le) of password
- MD4 hash of the above (This is also the NTLM Hash of the password)
- Unicode(utf-16le) and Uppercase of Username and Domain/Workgroup together 
- Calculating the ResponseKeyNT via HMAC_MD5(NTLM Hash, Unicode of User/Domain above)
- NTProofStr (can be calculated but not needed as it is present in the PCAP)
- Calculating the KeyExchangeKey via HMAC_MD5(ResponseKeyNT,NTProofStr)
- Decrypt the Encrypted Session Key via RC4 and the Key Exchange Key to finally get the Random Session Key

And, the guy was nice enough to write up the code to do it, called random_session_key_calc.py.

```
import hashlib
import hmac
import argparse

#stolen from impacket. Thank you all for your wonderful contributions to the community
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
   cipher = ARC4.new(keyExchangeKey)
   cipher_encrypt = cipher.encrypt

   sessionKey = cipher_encrypt(exportedSessionKey)
   return sessionKey
###

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u","--user",required=True,help="User name")
parser.add_argument("-d","--domain",required=True, help="Domain name")
parser.add_argument("-p","--password",required=True,help="Password of User")
parser.add_argument("-n","--ntproofstr",required=True,help="NTProofStr. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-k","--key",required=True,help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

args = parser.parse_args()

#Upper Case User and Domain
user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')

#Create 'NTLM' Hash of password
passw = args.password.encode('utf-16le')
hash1 = hashlib.new('md4', passw)
password = hash1.digest()

#Calculate the ResponseNTKey
h = hmac.new(password, digestmod=hashlib.md5)
h.update(user+domain)
respNTKey = h.digest()

#Use NTProofSTR and ResponseNTKey to calculate Key Excahnge Key
NTproofStr = args.ntproofstr.decode('hex')
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

#Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey,args.key.decode('hex'))

if args.verbose:
    print "USER WORK: " + user + "" + domain
    print "PASS HASH: " + password.encode('hex')
    print "RESP NT:   " + respNTKey.encode('hex')
    print "NT PROOF:  " + NTproofStr.encode('hex')
    print "KeyExKey:  " + KeyExchKey.encode('hex')    
print "Random SK: " + RsessKey.encode('hex')
```
I modified this code a little to add a -H to load the hash directly and format it for the process:
```
└──╼ #diff random_session_key_calc.py random_session_key_calc2.py 
25c25,26
< parser.add_argument("-p","--password",required=True,help="Password of User")
---
> parser.add_argument("-p","--password",required=False,help="Password of User")
> parser.add_argument("-H","--hash",required=False,help="Password Hash of User")
37,39c38,46
< passw = args.password.encode('utf-16le')
< hash1 = hashlib.new('md4', passw)
< password = hash1.digest()
---
> if args.password:
>     passw = args.password.encode('utf-16le')
>     hash1 = hashlib.new('md4', passw)
>     password = hash1.digest()
>     if not args.hash:
>         LOG.critical("Doesn't work without a password (-p) or at least a hash (-h)!! Exiting")
>         exit
> else:
>     password = args.hash.decode('hex')

```
(The last line above was initally incorrect, see below)

So, finally, the info I have is:
```
Account: athomson
Domain: CORP
Host: WS02
DC=corp-dc.CORP.local
NTProofStr: d047ccdffaeafb22f222e15e719a34d4
NTLM hash: 88d84bad705f61fcdea0d771301c3a7d
Session key: 032c9ca4f6908be613b240062936e2d2
Session ID:  0x0000a00000000015
```
-Set up the command:
```
└──╼ #python ./random_session_key_calc2.py  -u athomson -d CORP -H 88d84bad705f61fcdea0d771301c3a7d -n d047ccdffaeafb22f222e15e719a34d4 -k 032c9ca4f6908be613b240062936e2d2
Random SK: 7cea1298d002ede9bda40f60a5b4714a
```
VOILA!!!

But, the key didn't work! haha..  Of course it wouldn't, nothing ever works the first time.  I had to play around with the unknowns a bit, test assumptions, etc.
First, I noticed the Session ID: was reversed in the bytes of the PCAP from what Wireshark was telling me, so I tried doing the same: 

```
Session ID:
0x0000a00000000015
or:?? backwards?
0x1500000000a00000
```
OR RSK.. Tried using CORP.local as domain instead:
1faa3c87435762a0f9f160e83a859b50

Tested with a -verbose and noticed my hash was twice as long as it should have been.. Encoding error I think.  Proved correct, quick fix.

Just had to decode ascii to hex properly in the code: 
```
#    password = args.hash
    password = args.hash.decode('hex')
```	
Random SK: 9ae0af5c19ba0de2ddbe70881d4263ac

Nope, still not it. Shit.
Tried with the Session ID backwards again, instead of copying the value, used what bytes I saw below in the raw data:
`0x1500000000a00000`

Actual VOILA!!!  Session decrypted.  Looked and there is a pdf file copied, in the SMB export dialog:
![file xfer](https://github.com/crypticsilence/htb_business2022_ctf_writeups/blob/main/img/rogue-smb3_filexfer.png?raw=true)

Grabbed it and checked it out, found the flag!
![pdf and flag](https://github.com/crypticsilence/htb_business2022_ctf_writeups/blob/main/img/rogue-pdf_document.png?raw=true)

HTB{n0th1ng_c4n_st4y_un3ncrypt3d_f0r3v3r}

This took a lot longer than I had hoped because of the fact first off I was working with a bad zip file. I think when I extracted the from the ftp-data packets maybe I was missing a few at the bottom, or retransmissions messed it up, or somehow, I messed it up.  This actually happened twice, so at that point I thought that maybe I was supposed to figure out how to fish creds out of this corrupt minidump.  But, the 3rd time I extracted it everything started to come together.  The last part took a little tweaking to get it to work, but I knew I had everything I needed at that point.  Great challenge, lots of fun and a good learning experience!
