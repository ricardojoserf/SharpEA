# SharpEA

Read, write and delete Extended Attributes (EAs) to hide malicious payloads within NTFS filesystems.

### List EAs

```
SharpEA.exe list FILE_PATH
```

Example:

```
SharpEA.exe list c:\Windows\System32\kernel32.dll
```

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpea-screenshots/Screenshot_1.png)


### Write EA

The payload can be a string, a hexadecimal value or a url to download a file:

```
SharpEA.exe write FILE_PATH EA_NAME PAYLOAD
```

Example using a string:

```
SharpEA.exe write c:\Temp\test.txt EA_name1 RandomString
```

Example using a hexadecimal value (payload starts with "0x..."):

```
SharpEA.exe write c:\Temp\test.txt EA_name2 0x4142434445
```

Example using the content of a downloaded file (payload starts with "http..." or "https..."):

```
SharpEA.exe write c:\Temp\test.txt EA_name3 http://127.0.0.1:8000/a.bin
```

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpea-screenshots/Screenshot_2.png)


### Delete specific EA

```
SharpEA.exe delete FILE_PATH EA_NAME
```

Example:

```
SharpEA.exe delete c:\Temp\test.txt EA_name1
```


![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpea-screenshots/Screenshot_3.png)



### Clear all EAs

```
SharpEA.exe clear FILE_PATH
```

Example:

```
SharpEA.exe clear c:\Temp\test.txt
```


![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpea-screenshots/Screenshot_4.png)



--------------------------------------------------------

### Credits

This is based on C++ code from Sektor7's [Malware Development Advanced - Vol.1 course](https://institute.sektor7.net/rto-maldev-adv1).
