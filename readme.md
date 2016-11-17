
# ab_decrypt.py #
v 1.0

## Introduction ##

An educational python tool to decrypt Android backups (created using "adb backup"). 

Not memory optimized, as decryption and decompression are done in memory !

The tricky thing is to prepare the PBKDF2 secret value for password verification, as Java/Android implementation does byte to UTF16BE char to UTF8 strange conversions!

References documents:

- [Unpacking android backups](https://nelenkov.blogspot.fr/2012/06/unpacking-android-backups.html "Unpacking android backups"), Nikolay Elenkov, 8th June 2012
- [BackupManagerService.java](https://android.googlesource.com/platform/frameworks/base/+/master/services/backup/java/com/android/server/backup/BackupManagerService.java "BackupManagerService.java"), Android code source
- [Java Widening and Narrowing Primitive Conversion](https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.4 "Java Widening and Narrowing Primitive Conversion "), Java specification

Requirements : PyCrypto 2.6, Python 2.7.12. Tested with Android 5.1 and Android 7.0

Copyright Laurent Clévy (@lorenzo2472), november 2016

License is GPLv3

## Usage ##

    >py -2.7 ab_decrypt.py -h
    Usage: ab_decrypt.py [options]
    
    Options:
      -h, --helpshow this help message and exit
      -p PASSWORD, --pw=PASSWORD
    password
      -o OUTPUT, --out=OUTPUT
    output file
      -v VERBOSE, --verbose=VERBOSE
    verbose mode
      -b BACKUP, --backup=BACKUP
    input file
                        
### level 1 verbosity

    >py -2.7 ab_decrypt.py -b nexus4_20161101_1234.ab -p 1234 -v 1
    password verification is OK
    decrypting 176040976 bytes... OK
    decompression... done ( 263501824 bytes )
    writing backup as .tar ... OK. Filename is 'backup.tar'

### level 2 verbosity

to get crypto values, use **-v 2** :

    >py -2.7 ab_decrypt.py -b nexus4_20161101_1234.ab -p 1234 -v 2
    {'encryption': 'AES-256', 'version': '3', 'compression': '1'}
    user password salt: eff5fff9d380affdb615a1b8f0ff9aee96f63777c9931e61845a290447a2280514c481dcebe1ab6175d159ba1e2225f61275
    b44b8d2e3485a3b6e1ac1bb6f711
    master key checksum salt: 2faa6feaf812be9f0641613f8378fb890840aea00c8ead6d81a1c16127f02fb7c37907c3c88bc08ccd2cd70aed162c
    62fbdf9d2a0856c149ae5a7b9877d73347
    number of PBKDF2 rounds: 10000
    user key IV: e19804bb75fb9ccd0d7e09b1ee5e0173
    master key blob: 3d3fc39048cf5322f12db4ecf9374ec5059ee2e0565b5b24739c1fb7dbda902210197574d2c709874a7022673fd1a9b2e67e8b6
    0f4832be54bbd8aca130cbc184ffc4d7316e334f6fcf7eb28604c5d5c210464b8cc995c75d9be9dabf7dbfd35
    IV length: 16
    IV: 000bfc38507701b2babf008befd7a09b
    master key length: 32
    master key: de7afb611aeeea2c3e4b8a5841a7854b4d08aaedb0cacfbdf83eda5b1a807cba
    check value length: 32
    check value: 636dd3626057ebf16991eba31a0bc0d828809b7631ca866bac96d5ff853b7730
    PBKDF2 secret value for password verification is: efbf9e7aefbfbb611aefbfaeefbfaa2c3e4befbe8a5841efbea7efbe854b4d08efbeaa
    efbfadefbeb0efbf8aefbf8fefbebdefbfb83eefbf9a5b1aefbe807cefbeba
    password verification is OK
    decrypting 176040976 bytes... OK
    decompression... done ( 263501824 bytes )
    writing backup as .tar ... OK. Filename is 'backup.tar'

### unencrypted backups are supported too:

    >py -2.7 ab_decrypt.py -b nexus4_20161101_nopw.ab  -v 1 -o out.tar
    no encryption
    decompression... done ( 263516160 bytes )
    writing backup as .tar ... OK. Filename is 'out.tar'

