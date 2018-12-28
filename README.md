# NC3-CTF-2018-Writeup

I participated in the NC3 Christmas CTF under the name telenor (I was the only one from telenor participating sadly), ended in sixth place. These are some very quick writeups, so not very indepth.

The three challenges I did not complete were: 
* Breach (partial writeup)
* whosdaboss
* analyse - svær.

**Table of Contents:**

* [Reversing](#reversing)
   * [10 - Indledning](#10---indledning)
   * [50 - Små Skridt](#50---små-skridt)
   * [200 - nisse.elf](#200---nisseelf)
   * [400 - Fi1eCrypter](#400---fi1ecrypter)
   * [450 - Kan du dekode?](#450---kan-du-dekode)
* [Misc](#misc)
   * [150 - breach_nem](#150---breach_nem)
   * [350 - wallet](#350---wallet)
   * [500 - breach](#500---breach)
* [Analyse](#analyse)
   * [150 - nem](#150---nem)
   * [250 - whosdaboss](#250---whosdaboss)
   * [400 - svær](#400---svær)
* [Forensics](#forensics)
   * [75 - agurker_svær](#75---agurker_svær)
   * [150 - agurker](#150---agurker)
   * [100 - Detvarderengang](#100---detvarderengang)
   * [200 - NC3.jpg](#200---nc3jpg)
   * [350 - Billedchallenge.jpg](#350---billedchallengejpg)
* [boot2root](#boot2root)

# Reversing
## 10 - Indledning

**Description:** Hvordan mon kodenissen klarer den her?

**Hint:** Use the Force luke!

HTML file containing the following relevant code:

`if (reverseString(flagValue) == '}tlepmis_aas{3CN')`

Obviously just reverse the string.

**Flag:**  NC3{saa_simpelt}

## 50 - Små Skridt

**Description:** Lad os skrue lidt op for sværhedsgraden.

**Hint:** Baggrundslæsning: https://en.wikipedia.org/wiki/Bitwise_operation#XOR

Nyttigt værktøj til CTF-opgaver: https://gchq.github.io/CyberChef/

HTML file containing the following relevant code:

`xorFlag += String.fromCharCode(128 ^ flagValue.charCodeAt(i));`
...
`if (xorFlag == atob("zsOz+/Nl3+Xy3/bp3+nf5+Hu5/0="))`

Flag has been XOR'd with 128, so XOR it again with 128 to reverse.

```python
from base64 import b64decode
bin = b64decode("zsOz+/Nl3+Xy3/bp3+nf5+Hu5/0=")
[print(chr(x^128), end="") for x in bin]
```

**Flag:** NC3{så_er_vi_i_gang}

## 200 - nisse.elf

**Description:** En livlig nisse har lavet en crackme, som han rigtig gerne vil vise frem.

**Hint:** 
>Strings/Grep e.l. er ikke nok. Prøv at åbne filen i en disassembler, f.eks. Ida Pro Free. Assemblerkoden har symboler, dvs. programmørens funktionsnavne er synlige. Ud fra dette kan man udlede hvilken funktion, der tjekker for den mellemste del af flaget.

Open in IDA, the first and third part of the flag should be obvious, even more so if using the decompiler (F5). Relevant assembly under:

Part 1:
`mov     edi, offset _ZZ15ErKodeordetSejtPKcE11s_flagStart ; "NC3{koden_er_fin__"`

Part 2:
```asm
cmp     al, 6Eh // 'n'
cmp     al, 63h // 'c'
cmp     al, 33h // '3'
```

Part 3:
`mov     esi, offset _ZZ15ErKodeordetSejtPKcE9s_flagEnd ; "__og_nu_er_den_min}"`


**Flag:** NC3{koden_er_fin__nc3__og_nu_er_den_min}

## 400 - Fi1eCrypter

**Description:** 
>Åh nej! En unavngiven person har fået fingrene i noget ransomware. Umiddelbart går den MEGET målrettet efter noget på ofrets computer.
>Vi har fået adgang til en krypteret fil. Kan du dekryptere den?

**Hint:** 
>En disassembler (såsom Ida Pro Free) kan bruges. Dog er der ikke symboler i .exe-filen, dvs. man skal læse lidt mere af assemblerkoden før man når til krypteringen. Denne kryptering skal derefter "reverses", dvs. gøres i omvendt rækkefølge.
>Opgaven er også blevet løst ved ren analyse af den krypterede fil.

**Solution:** 
We get an .exe and a file with the encrypted data. Again, IDA does a great job and makes it almost too easy, especially with the decompiler.

In main, the second function call is the relevant one:

`.text:0000000140001330                 call    sub_140001000`

If we take a quick look at the function, we want to find something that loops over data. The following is the first tight loop, which also does add and xor, which looks promising:

```asm
loc_1400010E0:
mov     eax, edx
vpaddb  xmm1, xmm3, [rsp+rax+460h+Buffer]
vpxor   xmm2, xmm1, xmm4
vmovdqu [rsp+rax+460h+Buffer], xmm2
lea     eax, [rdx+10h]
add     edx, 20h
vpaddb  xmm1, xmm3, [rsp+rax+460h+Buffer]
vpxor   xmm2, xmm1, xmm4
vmovdqu [rsp+rax+460h+Buffer], xmm2
cmp     edx, r9d
jb      short loc_1400010E0
```

Don't let the vector registers scare you. If we check out what the vpaddb and vpxor instructions add and xor with, we find the following:

```asm
.rdata:0000000140016360 xmmword_140016360 xmmword 1010101010101010101010101010101h
.rdata:0000000140016370 xmmword_140016370 xmmword 90909090909090909090909090909090h
```

Let's just try to decrypt the content of the file, doing this in reverse:

data = open("encrypted_flag.txt.ENCRYPTED", "rb").read()

```python
for x in data:
	x = x^0x90
	x = x-0x01
	print(chr(x&0xff), end="")
```

Works.

**Flag:** NC3{kan_du_lide_min_kryptering??}

## 450 - Kan du dekode?

**Description:** 
>Bad guys og deres kodeordsbeskyttede sider.

**Solution:** 

You are given a .php file that takes a password and decrypts the data in the $krypteret_indhold variable.

The relevant part of the code is this:

```php
for($i = 0; $i < strlen($krypteret_indhold); $i++)
{
	$currentKodeordChar = ord($kodeord[$i % strlen($kodeord)]);
	$dekrypteret_indhold .= chr( (ord($krypteret_indhold[$i]) ^ $currentKodeordChar) % 256 );
}
```

This is a simple repeating key XOR encryption. This type of XOR encryption is vulnerable to known [known plaintext attacks](https://en.wikipedia.org/wiki/Known-plaintext_attack). To break it I used the first and best crib-dragging script I found ([here](https://github.com/SpiderLabs/cribdrag)). Crib dragging is the process of taking a known plaintext, XOR'ing it at all possible offsets and looking for familiar text in the key. 

Call the script with the data from $krypteret_indhold and start by guessing that NC3{ is a part of the decrypted text. Enter it into the script when it asks for the crib. There are 110 possible offsets with this key length. If inserted at line 48, the resulting key would be 'gern', this could be a danish word 'gerne'. Save it as a part of the message, then try to enter 'gerne' as the crib. At offset 6 we see '\<bod'. This looks like HTML, lets save it and try to enter \<body\>. Here we find 'gernein' as a part of the key. From here I actually just guessed the rest, as letmein is a common password. So the password is 'jegvilgerneind'. Decrypt the string and you get some HTML with a flag.

**Flag:** NC3{dekodning_af_kodede_php_bytes}

# Misc

## 150 - breach_nem

**Description:** Der blev opfanget noget trafik på kablerne ...

Open the pcap file with wireshark. Find the first TCP package, right click -> follow -> tcp stream. Cycle the streams until you find this conversation:

>har du noget til mig?
>guldjul
>eh?
>https://ghostbin.com/paste/jnmo7kys
>MUHAAAAA!!!
>:)

Open the link and use guldjul as password. The flag looks like this: AP3{avffre_cå_yvawra__iv_fre_serz_gvy_jevgrhcf}. This is clearly rot13. Just rot13 it and get the flag.

**Flag:**  NC3{nisser_på_linjen__vi_ser_frem_til_writeups}

## 350 - wallet

**Description:** Bit bit

You are provided a wallet.dat file. It is a bitcoin wallet. Just grep or otherwise dump the bitcoin addresses, there should be three or something like that. Look them up on blockchain.com. Keep following the transactions (outgoing) until you find a transaction with data hidden in the output scripts (didn't write it down, just click around). The transaction should be ce4c5dfe1f0ec95d7ed5030bb9954f8950455b1fdd0849471c76ac09502b2b1a. Remember to press "Show scripts & coinbase" on blockhain.com.

Here you will find the following data:
```
RETURN PUSHDATA(57)[455720466c61673a20546b4d7a6532357063334e6c626e4e665347463359576c705832526c6347397a61585266595752795a584e7a5a58303d]
(decoded) EW Flag: TkMze25pc3NlbnNfSGF3YWlpX2RlcG9zaXRfYWRyZXNzZX0=
```

Base64 decode and get the flag.

**Flag:**  NC3{nissens_Hawaii_deposit_adresse}

## 500 - breach

**Description:** Åh åhh, breached! Der blev opfanget noget trafik på kablerne som måske er nyttigt ...

**Hint:** Programmets korrekte output er store bogstaver mellem A-P.

**Solution:**
I almost finished this, but the CTF stopped, so I lost interest. I'll describe the reversing part briefly.

You get a wireshark file again. Find the HTTP requests, until you find a file download. Save the binary, which is a mips64 (BE) binary for Linux.

To run the .exe you can use qemu-mips64-static file.elf <input>. The program outputs:

>CRUnCH1NG ...
>Velfortjent flag: <224 char long string of characters>.

To reverse the file you can run the binary with qemu-mips64-static -g port file.elf <input> and then remotely attach from IDA Pro (Both gdb-multiarch and radare2 didn't work for me with mips64 big endian).

After using way too much time stepping through the code in IDA Pro ... which like gdb and radare2 is not really happy about debugging mips64, some registers are misnamed, causing crashes if you hover over them, you have to add your own memory maps for stack and heap, etc. Anyway, after using way too much time, find that the decryption function is at 0000000120003E50, then just reverse it:

![Reversed](https://i.imgur.com/uP8BcMg.png "Reversed")

Okay, so it's basically just repeating XOR with a little change:
```
encrypted_char += 0x18
res = x ^ password_char
res = res-1
```

After some trial and error, and after reading the hint that I missed, I first identified the password length, then I just bruteforced each character in the 23 char password, as the search space for each is pretty low (the result has to be between A and P). This gave the password julemandenkommertilbyen, which results in the following output:

```
Velfortjent flag:
OLEOKIANJLDOOAEFIJCMOGEDJCDHMNGIKEABMLGOLPBKOAEFIJCMOGEDJCDHMNGIJCDHPFFAJJDMHPNKBLLOHONLBCLHHLNOBMLJEDOGCJIMFMPJDAJFGPMKDAJFEGODCPIKHANFADKGGGMDBELBELOOCNIIFPPKDKJPFHPCAIKNHMNJBFLAHJNMCGIDFBPECDIGEKOPDOJLFLPOCOILFOPLCNIIFAPF
```

This was the night before the CTF ended, didn't have anymore time, so I just gave up.

**Flag:**  ???

# Analyse
## 150 - nem

**Description:** Datagraveri. Julemanden har fundet en ny måde at gemme kodeordet til slikskabet. Bemærk at flaget starter med småt: nc3{

**Hint:** Der er kun en relevant kolonne med tal - resten er junk.

I did this one before the hint. You get a csv file with about 100 columns and 10001 rows. The first column contains random chars in the printable range. The rest of the columns contains numbers between 10001. So the numbers should obviously be replace with the chars, this can be done like this:

```python
import csv

data = open("analyse_nem.csv")
output = open("output.csv", "w+")
csv_reader = csv.reader(data, delimiter=";")
csv_writer = csv.writer(output, delimiter=";")

chars = [row[0] for row in csv_reader]
data.seek(0)
data = [row[1:] for row in csv_reader]

for row in data:
	row = [chars[round(float(x.replace(",", ".")))-1] for x in row]

	csv_writer.writerow(row)
```

You can open the resultant csv in excel (I was lazy) and then just look at the columns until you find one that starts with nc3{ downwards.

**Flag:**  nc3{The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents. We live on a placid island of ignorance in the midst of black seas of infinity, and it was not meant that we should voyage far. H.P. Lovecraft}

## 250 - whosdaboss

**Description:** Julemanden havde fået mistanke om et hemmeligt netværk af sortnisser, der forsøgte at overtage gaveproduktionen og sælge den til højestbydende kapitalfond. Men hvem er lederen af netværket?

No idea, this was the most frustrating challenge for me, as I am sure I was just missing something simple.

**Flag:**  ???

## 400 - svær

**Description:** Endnu mere datagraveri. Var en kolonne ikke nok? Julemanden måtte gøre koden til slikskabet endnu sværere.

Again, no idea.

# Forensics

## 75 - agurker_svær

**Description:** Nisserne siger at man med fordel kan løse den anden agurk først. Men what, den her giver jo færre point, men skulle være sværere? Makes no sense at all

**Solution:**

You get a binary file. I have no idea how you are supposed to solve this, but it looks like some sort of struct. What I did was look at the hex, split it by '94', so you end up with something like this (header removed and the top line after):

```
944b118c023734
944b018c023030
944b038c023433
944b058c023762
944b0a8c023663
944b068c023530
944b028c023465
944b078c023639
944b0d8c023532
944b098c023662
944b0f8c023735
944b0b8c023635
944b048c023333
944b0c8c023566
944b0e8c023533
944b088c023633
944b128c023731
    xx  zzyyyy
```

xx in the above is an index, so sort (hex) by these values. zz is the length of the numbers after (2 in this case for two hex bytes). yyyy are the numbers we care about (after sort). Copy all these hex values, do hex to char on them, then you'll get something like this: 004e43337b5069636b6c655f5253757471. Then hex to char them again, and you'll get the flag.

**Flag:** NC3{Pickle_RSutq

## 150 - agurker

**Description:** Julemanden har lidt svært med de der filtyper, som han bruger når han skal printe labels til den årlige produktion af syltede agurker med kommen. "Hvordan åbner jeg det her gylle?" tænkte Julemanden inden han gik ud for at gurgle munden i lagereddike. OBS KUN 2 FORSØG TIL DENNE OPGAVE

**Solution:**

Again, not sure how you are supposed to do it, but who cares :)

Split by 94 again, and you get something like this:
```
800495a7000000000000007d
948    c01 31
948    c02 3030
948    c01 32
948    c02 3465
948    c01 33
948    c02 3433
948    c01 34
948    c02 3333
948    c01 35
948    c02 3762
948    c01 36
948    c02 3530
948    c01 37
948    c02 3639
948    c01 38
948    c02 3633
948    c01 39
948    c02 3662
948    c02 3130
948    c02 3663
948    c02 3131
948    c02 3635
948    c02 3132
948    c02 3566
948    c02 3133
948    c02 3532
948    c02 3134
94680e8c02 3135
9468108c02 3136
9468128c02 3137
948    c02 3764
948    c02 3138
948    c02 3731
94752e
        xx zzyy
```

xx is the amount of bytes 1 or 2, which are denoted by zz and yy. Take every second value starting with 3030. Hex to char, hex to char again, then you get NC3{Pickle_R}q. The bottom is obviously in the wrong order, but I just guessed Pickle_Rick, which was correct, so didn't bother anymore.

**Flag:** NC3{Pickle_Rick}

## 100 - Detvarderengang

**Description:** Flaget var gemt i tekstfilen, men nisserne drillede og slettede flaget i filen. Kan det stadig findes?

**Solution:**

You get a file named Detvarderengang.dd. Run file on it:

```
DOS/MBR boot sector, code offset 0x52+2, OEM-ID "NTFS    ", sectors/cluster 8, Media descriptor 0xf8, sectors/track 1, heads 1, dos < 4.0 BootSector (0x80), FAT (1Y bit by descriptor); NTFS, sectors/track 1, sectors 9727, $MFT start cluster 405, $MFTMirror start cluster 2, bytes/RecordSegment 2^(-1*246), clusters/index block 1, serial number 0aace64a4ce646a91
```

It's a NTFS file. Mount it with (create mountpoint first):

```
mount -t ntfs -o loop,ro Detvarderengang.dd /mnt/Detvarderengang
```

There is a file called Flaget.txt which contains the text `Flaget er: `. 

Grep for the flag in the raw file:

```
grep --text -a -F 'Flag' ~/Detvarderengang.dd
```

There's a lot of really long lines to throw you off, but the relevant result is at the bottom, so you can just ignore it.

```
Flaget er 078 067 051 123 102 105 108 121 115 116 101 109 095 105 110 116 101 116 095 112 114 111 098 108 101 109 125
```

Convert from byte to char:

```
>>> [print(chr(int(x)), end="") for x in "078 067 051 123 102 105 108 121 115 116 101 109 095 105 110 116 101 116 095 112 114 111 098 108 101 109 125".split(" ")]
NC3{filystem_intet_problem}
```

**Flag:** NC3{filystem_intet_problem}

## 200 - NC3.jpg

**Description:** Et helt uskyldigt billede

**Solution:**

You get a boring image. Binwalk doesn't find anything hidden inside, so that usually means some sort og steganography. I just tried different tools until I tried https://github.com/Paradoxis/StegCracker which just runs steghide with a password list. So run it:

```
➜  ~ ./stegcracker NC3.jpg rockyou.txt
StegCracker - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2018 - Luke Paris (Paradoxis)

Attacking file 'NC3.jpg' with wordlist 'rockyou.txt'..
Successfully cracked file with password: password1
Your file has been written to: NC3.jpg.out
```

The text in the output file is clearly base64, so decode:

```
base64 --decode NC3.jpg.out > output.txt
```

The output looks like this (longer than the sample here):

```
.-.-.- .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- .-.-.-
```

It's pretty obviously morse, so hit up google and find the first and the best morse code translator. You then end up with:

```
....................!?.?...?.......?...............?....................?.?.?.?.!!?!.?.?.?........................!..?..........!.?.?.....!..?.?......................!.!!!!!!!!!!!.!!!!!!!!!!!!!!!!!!!!!!!!!!!.................................!.!!!!!!!!!!!!!!!!!!!!!.?.?.!..?.?........................!.............!.!!!!!!!!!!!!!!!!!!!!!!!.............!.!!!!!.!!!!!!!!!!!!!!!!!!!!!!!.?.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!.?.!..?................!...............................!.?.......................................!..?.?......................................!.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!.................!.!.?.............................!.................!.!!!!!!!!!!!..?!.....................!.!.!!!!!!!!!!!!!.?.........!.!!!!!!!!!!!!!!!..?!!!!!!!!!!!!!!!!!!!...........................!.?.!.................!.................!.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!.!..?!!!!!!!!!.?.!!!!!.................!.!!!!!!!.....!.!!!!!!!..?....!.................!.
```

Looks kinda [Brainfucky](https://en.wikipedia.org/wiki/Brainfuck). I the just googled `esoteric language question mark exclamation mark`, first result (for me) was this [translator](https://www.dcode.fr/ook-language). The esolang is [Ook!](https://esolangs.org/wiki/ook!). Plop the text in the translator and you get:

```Ri tobrh tzoush: BQ3{goo_gboyysf_jw_goaas_gdfcu}```

Looks like rot13. It's not though, it's rot12. I always just use https://www.rot13.com/ and scroll on the select box. Anyway, we got the flag.

**Flag:** NC3{saa_snakker_vi_samme_sprog}

## 350 - Billedchallenge.jpg

**Description:** Noget er ikke som det plejer

**Solution:**

We get an image again, this time there is a missing or corrupted part in the bottom corner. This time binwalk is helpful however, and  reports multiple JPEG images:

```
➜  ~ binwalk Billedechallenge.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
22327         0x5737          JPEG image data, JFIF standard 1.01
22357         0x5755          TIFF image data, big-endian, offset of first image directory: 8
22759         0x58E7          JPEG image data, JFIF standard 1.01
22789         0x5905          TIFF image data, big-endian, offset of first image directory: 8
26192         0x6650          JPEG image data, JFIF standard 1.01
```

Let's try to just extract all the ranges:

```
binwalk --dd=".*" Billedechallenge.jpg
```

Out of the chunks in the output folder, there are two images that open:

58e7:
![1](https://i.imgur.com/Aq3x2iC.jpg "1")

6650:
![2](https://i.imgur.com/8Xzs7u1.jpg "2")

Okay, so we probably just need to rearrange the parts. The rest I just did in a hex editor by hand. Finding jpeg start of image (FF D8) and end of image (FF D9) byte sequences, and mixing and matching. One of the chunks was missing it's data, which was located elsewhere in the file, outside of the jpeg structs. Move it back and you get the last part of the flag:

![3](https://i.imgur.com/OksVSnN.jpg "3")

Put them together and you get the flag.

**Flag:** NC3{billede_i_3_dele}

# boot2root

Well these challenges were a mess. I'm not sure what went wrong, but it seems like NC3 didn't realize or forgot that everyone knows you can just tell grub to give you a root shell by adding `init=/bin/bash` to the boot script. So there was never a reason to get the IP of the machine (as NC3 wrote in the description). By looking at the challenges, you can clearly see the path they intended you to take, and that you were supposed to access the box over the network, gain user access and the get root access.

So I'm not going to do a writeup, as I didn't sove them the intended way. There was one challenge where you had to reverse a packed .exe, but you just had to run upx -d on it, and the reverse it, and it was really not a big deal. One other flag was stored in mysql running on the machine (username/password in a .php script in /var/www somewhere). The last two flags just required you to su to a user and remount their encrypted files. Then the two flags were just sitting there to read.

So yeah, disappointing really, it could have been some cool challenges.
