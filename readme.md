
# ab_decrypt.py #
v 1.1

## Introduction ##

An educational python tool to decrypt Android backups (created using "adb backup"). 

Not memory optimized, as decryption and decompression are done in memory !

The tricky thing is to prepare the PBKDF2 secret value for password verification, as Java/Android implementation does byte to UTF16BE char to UTF8 strange conversions!

References documents:

- [Unpacking android backups](https://nelenkov.blogspot.fr/2012/06/unpacking-android-backups.html "Unpacking android backups"), Nikolay Elenkov, 8th June 2012
- [BackupManagerService.java](https://android.googlesource.com/platform/frameworks/base/+/master/services/backup/java/com/android/server/backup/BackupManagerService.java "BackupManagerService.java"), Android code source
- [Java Widening and Narrowing Primitive Conversion](https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.4 "Java Widening and Narrowing Primitive Conversion "), Java specification

Requirements : PyCryptoDome 3.9.0, Python 3.7.3. Tested with Android 5.1,  7.0 and 8.1 backups.

Copyright Laurent Clévy (@lorenzo2472), november 2016

License is GPLv3

## Contributions ## 

- Glenn Wasbhurn (@crass) : reading and decompressing using chunks, for efficient memory usage. Better code organisation

## Backup tool

adb tool can be downloaded from https://developer.android.com/studio/releases/platform-tools



## Usage ##

    >python ab_decrypt.py -h
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

    >python ab_decrypt.py -b nexus4_20161101_1234.ab -p 1234 -v 1
    password verification is OK
    decrypting 176040976 bytes... OK
    decompression... done ( 263501824 bytes )
    writing backup as .tar ... OK. Filename is 'backup.tar'

### level 2 verbosity

to get crypto values, use **-v 2** :

    >python ab_decrypt.py -b nexus4_20161101_1234.ab -p 1234 -v 2
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
    
    >python ab_decrypt.py -v 2 -p 1234 -b i:\dev\platform-tools_r30.0.0-windows\platform-tools\backup.ab
    {'version': b'5', 'compression': b'1', 'encryption': b'AES-256'}
    user password salt: b'e126eddc7772e044d31b78429961c3fd36900fb0467b55fa22f569c851dab56bd6c5c7bf4df194c3ff5572d67ab243567d7a732d76484a5d5813df28db20a44a'
    master key checksum salt: b'a10883dceadbffd6d1b73c74c58633e2f018c679a25b62773c4965eff2aa3ff8b6d35ac520463e2f7c3ad7ff319b092aaddab8a4287ade365bd70b2d2ced60eb'
    number of PBKDF2 rounds: 10000
    user key IV: b'1b2dc97e1eb6377fd984318e2b12cc10'
    master key blob: b'e2bbd7aa2612812e4d89f9637899bd6e649d701f899803713ddc455f34736ea3e39fd6c6ee0e817e636de36082cb441214a53ecc7d16f3dd26bdf95b833e901c5f7d97debde9842d602cf635245f04839ae2e7f26f9cfd5804ba4100d698049b'
    IV length: 16
    IV: b'131e7c02716b0db57e6624d10cb174bc'
    master key length: 32
    master key: b'52155e98c52a173eee635ebbded652cea999fa218e9083bd775f2dcdd1235f67'
    check value length: 32
    check value: b'660ff9040b56f3a7eda6ac1fcafdbd72e28762cff2af5fc93b5969cf9f2b6303'
    PBKDF2 secret value for password verification is: b'52155eefbe98efbf852a173eefbfae635eefbebbefbf9eefbf9652efbf8eefbea9efbe99efbfba21efbe8eefbe90efbe83efbebd775f2defbf8defbf91235f67'
    password verification is OK
    decrypting 406437680 bytes... OK
    decompression... done ( 580716032 bytes )
    writing backup as .tar ... OK. Filename is 'backup.tar'

### unencrypted backups are supported too:

    >python ab_decrypt.py -b nexus4_20161101_nopw.ab  -v 1 -o out.tar
    no encryption
    decompression... done ( 263516160 bytes )
    writing backup as .tar ... OK. Filename is 'out.tar'

