# Cross Platform AES 256 GCM Encryption / Decryption (Windows x64 C++ dynamic library)

![C# Test](/GcmAes.png)

### Introduction
While working in security, identity management and data protection fields for a while, I found a very few working examples in the public domain on cross platform encryption based on AES 256 GCM algorithm. This is the same algorithm used by Google when you access Gmail, etc.

This article may help you implement very strong cross platform encryption / decryption. The sample code is in C++, C# and Java. However, Java through JNI (Java Native Interface) and C# through COM, can call native C++ code, which in my testing appears to be much faster as compared to pure Java or C# implementations. Still, there are times when one wants to do it without calling a native C++ layer.


### Using the Code
This repository consists 2 **Microsoft Visual Studio 2022 projects**. Please clone the repository and open project **.sln** file in Visual Studio 2022 IDE.

### Build Steps:

### Crypto++:
Set **AesGcmTest** as startup project and build it (Debug x64 or Release x64). This project has other projects as depedency and all projects will be build in required build order including **Crypto++** library.

The test program validates few encryption and decryption tests. One of them is the decryption of text which was encrypted using Java code (links available below).

It produce following sample test results:

```
Key=94EC8EC06F82F1CEFF7C107B892B3C5C9483F65F8E9C70AF533C497CD578E7AD
Len=64

IV=E05985296C3701AB96A5E7408F0D5A70
Len=32
Key and IV Test OK

Test 1 -> Encrypted base64 encoded: Bpr6R7a1VZ/6qEILPnFSJC9kQ5iUEBR21/n3M6KTEVj41DcxTZJQQNqlYbGdmA==
Test 1 -> Decrypted: Test encryption and decryption
Test 1 -> Encryption / Decryption OK

Plain Text: Test encryption and decryption
Test 2 -> Encrypted base64 encoded: A/boAixWJKflKviHp2cfDl6l/xn1qw2MsHcKFkrOfm2XOVmawIFct4fS1w7wKw==
Test 2 -> Decrypted: Test encryption and decryption
Test 2 -> Encryption / Decryption OK

Test 3 -> Decrypted: Test encryption and decryption
Test 3 -> Java Encrypted / C++ Decryption OK

Test 4 -> Multi-byte Text: syllabic kana – hiragana (平仮名) and katakana (片仮名)
Test 4 -> Hex Encoded: 73796C6C61626963206B616E6120E28093206869726167616E612028E5B9B3E4BBAEE5908D2920616E64206B6174616B616E612028E78987E4BBAEE5908D29
Test 4 -> Hex Encoding OK

Test 5 -> Multi-byte Text: syllabic kana – hiragana (平仮名) and katakana (片仮名)
Test 5 -> Hex Decoded: syllabic kana – hiragana (平仮名) and katakana (片仮名)
Test 5 -> Hex Decoding OK

Test 6 -> Multi-byte Text: syllabic kana – hiragana (平仮名) and katakana (片仮名)
Test 6 -> Base64 Encoded: c3lsbGFiaWMga2FuYSDigJMgaGlyYWdhbmEgKOW5s+S7ruWQjSkgYW5kIGthdGFrYW5hICjniYfku67lkI0p
Test 6 -> Base64 Encoding OK

Test 7 -> Multi-byte Text: syllabic kana – hiragana (平仮名) and katakana (片仮名)
Test 7 -> Base64 Decoded: syllabic kana – hiragana (平仮名) and katakana (片仮名)
Test 7 -> Base64 Decoding OK
```

The test project also demonstrates how to use the **AesGcm.dll** with other C++ projects on Windows. Code uses **C++ 14** standard. **AesGcm.dll** itself is statically linked with Crypto++ library. **AesGcm.dll** can be used with other languages like C#, NodeJS and Java etc on Windows. For ### [Linux x64](https://github.com/KashifMushtaq/AesGcm_Linux) please use Linux version. 

### Background

[Cross Platform AES 256 GCM Encryption and Decryption (C++, C# and Java)](https://www.codeproject.com/Articles/1265115/Cross-Platform-AES-256-GCM-Encryption-Decryption)

You can also read more about Crypto++ AES GCM implementation or algorithm itself here and [here](https://www.cryptopp.com/).


### Related Projects:

### [C# Version](https://github.com/KashifMushtaq/AesGcm256)
### [C++ Version](https://github.com/KashifMushtaq/AES_GCM_256_C)
### [Java Version](https://github.com/KashifMushtaq/Aes256GCM_Java)
### [Linux Lib](https://github.com/KashifMushtaq/AesGcm_Linux)
### [Windows DLL](https://github.com/KashifMushtaq/AesGcm_Windows)
