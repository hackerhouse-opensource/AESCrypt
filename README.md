# AESCrypt

AESCrypt implementation of Microsoft Cryptography API, encrypt/decrypt with AES-256 from a passphrase.

Example use.

``` PS C:\Users\Fantastic\source\repos\AESCrypt\x64\Release> echo 1234 > secret.txt
PS C:\Users\Fantastic\source\repos\AESCrypt\x64\Release> .\AESCrypt.exe .\secret.txt howami encrypt
Performing operation: Encrypting file
Performing operation: Deriving key from password
Derived key:
eb 4a 5c d0 b7 3d bf b8 5e 8c 59 b6 92 b4 5b c2
c4 fd f2 41 92 32 6d 8c da 37 d7 02 e0 b3 01 c6
Performing operation: Generating random bytes
Random bytes generated:
17 32 b9 8a 6f 3e 83 bb ae f1 60 b4 1b 0b 93 3c
Encryption successful.
PS C:\Users\Fantastic\source\repos\AESCrypt\x64\Release> .\AESCrypt.exe .\secret.txt.enc howami decrypt
Performing operation: Decrypting file
IV:
17 32 b9 8a 6f 3e 83 bb ae f1 60 b4 1b 0b 93 3c
Performing operation: Deriving key from password
Derived key:
eb 4a 5c d0 b7 3d bf b8 5e 8c 59 b6 92 b4 5b c2
c4 fd f2 41 92 32 6d 8c da 37 d7 02 e0 b3 01 c6
Decryption successful.

PS C:\Users\Fantastic\source\repos\AESCrypt\x64\Release> type .\secret.txt.enc
2¹Šo>ƒ»®ñ`´

<¸ÓmHðç©Ù?xt¢;
PS C:\Users\Fantastic\source\repos\AESCrypt\x64\Release> type .\secret.txt.enc.dec
1234
```

# License

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.