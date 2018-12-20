# NC3-CTF-2018-Writeup

I participated in the NC3 Christmas CTF under the name telenor (I was the only one from telenor participating sadly). These are some very quick writeups, so not very indepth.

##### 10 - Indledning
---

**Description:** Hvordan mon kodenissen klarer den her?
**Hint:** Use the Force luke!

HTML file containing the following relevant code:

`if (reverseString(flagValue) == '}tlepmis_aas{3CN')`

Obviously just reverse the string.

**Flag:**  NC3{saa_simpelt}

##### 50 - Små Skridt
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

