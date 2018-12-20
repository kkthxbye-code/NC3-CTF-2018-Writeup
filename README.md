# NC3-CTF-2018-Writeup

I participated in the NC3 Christmas CTF under the name telenor (I was the only one from telenor participating sadly). These are some very quick writeups, so not very indepth.

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
**Hint:** Strings/Grep e.l. er ikke nok. Prøv at åbne filen i en disassembler, f.eks. Ida Pro Free. Assemblerkoden har symboler, dvs. programmørens funktionsnavne er synlige. Ud fra dette kan man udlede hvilken funktion, der tjekker for den mellemste del af flaget.

Open in IDA, the first and third part of the flag should be obvious when using IDA, even more so if using the decompiler (F5). Relevant assembly under:

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
guldjul
eh?
https://ghostbin.com/paste/jnmo7kys
MUHAAAAA!!!
:)

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
Velfortjent flag: <124 char long string of characters>.

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
Velfortjent flag: OLEOKIANJLDOOAEFIJCMOGEDJCDHMNGIKEABMLGOLPBKOAEFIJCMOGEDJCDHMNGIJCDHPFFAJJDMHPNKBLLOHONLBCLHHLNOBMLJEDOGCJIMFMPJDAJFGPMKDAJFEGODCPIKHANFADKGGGMDBELBELOOCNIIFPPKDKJPFHPCAIKNHMNJBFLAHJNMCGIDFBPECDIGEKOPDOJLFLPOCOILFOPLCNIIFAPF
```

This was the night before the CTF ended, didn't have anymore time, so I just gave up.

**Flag:**  ???
