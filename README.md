# SharpEA

Read, write and delete Extended Attributes (EAs) to hide malicious payloads within NTFS filesystems.

### List EAs

```
SharpEA.exe list FILE_PATH
```

Example:

```
SharpEA.exe list c:\Temp\test.txt
```

### Write EA

```
SharpEA.exe write FILE_PATH EA_NAME PAYLOAD
```

Example using a string:

```
SharpEA.exe write c:\Temp\test.txt EA_name1 RandomString
```

### Delete specific EA

```
SharpEA.exe delete FILE_PATH EA_NAME
```

Example:

```
SharpEA.exe delete c:\Temp\test.txt EA_name1
```


### Clear all EAs

```
SharpEA.exe clear FILE_PATH
```

Example:

```
SharpEA.exe clear c:\Temp\test.txt
```


--------------------------------------------------------

### Credits

This is based on C++ code from Sektor7's [Malware Development Advanced - Vol.1 course](https://institute.sektor7.net/rto-maldev-adv1).
