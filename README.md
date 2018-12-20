# NC3-CTF-2018-Writeup

I participated in the NC3 Christmas CTF under the name telenor (I was the only one from telenor participating sadly). These are some very quick writeups, so not very indepth.

## 10 - Indledning
---

**Description:** Hvordan mon kodenissen klarer den her?
**Hint:** Use the Force luke!

HTML file containing the following relevant code:

`if (reverseString(flagValue) == '}tlepmis_aas{3CN')`

Obviously just reverse the string.

**Flag:**  NC3{saa_simpelt}

## 50 - Små Skridt
---

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
---

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
