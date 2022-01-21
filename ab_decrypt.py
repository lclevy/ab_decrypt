# ab_decrypt.py
# to decrypt Android backups done using "adb backup"
# lclevy@free.fr (@lorenzo2472) Nov 2016
# requirements : PyCryptoDome 3.9.0, Python 3.7.3
# not memory optimized, as decryption and decompression are done in memory !
# checked with Android 5.1, 7.0 and 8.0
# references:
#  https://nelenkov.blogspot.fr/2012/06/unpacking-android-backups.html
#  https://android.googlesource.com/platform/frameworks/base/+/master/services/backup/java/com/android/server/backup/BackupManagerService.java

#from __future__ import print_function

import sys
import platform
import zlib
from binascii import unhexlify, hexlify
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from optparse import OptionParser
import codecs
from struct import pack
import ctypes

CHUNK_SIZE=128*1024

def inputtty(prompt=""):
  if platform.system() == "Windows":
    return input(prompt)
  with open('/dev/tty', 'rb') as ftty:
    if prompt:
      with open('/dev/tty', 'wb') as fwtty:
        fwtty.write(prompt.encode('utf8'))
        fwtty.flush()
    return ftty.readline().decode('utf8').rstrip("\n")

def masterKeyJavaConversion(k):
  """
  because of byte to Java char before using password data as PBKDF2 key, special handling is required
    
  from : https://android.googlesource.com/platform/frameworks/base/+/master/services/backup/java/com/android/server/backup/BackupManagerService.java  
      private byte[] makeKeyChecksum(byte[] pwBytes, byte[] salt, int rounds) {
        char[] mkAsChar = new char[pwBytes.length];
        for (int i = 0; i < pwBytes.length; i++) {
            mkAsChar[i] = (char) pwBytes[i];               <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< HERE
        }
        Key checksum = buildCharArrayKey(mkAsChar, salt, rounds);
        return checksum.getEncoded();
    }
      
  Java byte to char conversion (as "Widening and Narrowing Primitive Conversion") is defined here:
     https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.4
     First, the byte is converted to an int via widening primitive conversion (chapter 5.1.2), 
     and then the resulting int is converted to a char by narrowing primitive conversion (chapter 5.1.3) 
     
  """
  # Widening Primitive Conversion : https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.2
  toSigned = [ ctypes.c_byte(x).value for x in k ] #sign extension
  if options.verbose>2: print(toSigned)
  # Narrowing Primitive Conversion : https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.3
  toUnsigned16bits = [ ctypes.c_ushort(x).value & 0xffff for x in toSigned ]
  if options.verbose>2:
    for c in toUnsigned16bits: print('%x ' % c,end='')
    print('')  
  """ 
  The Java programming language represents text in sequences of 16-bit code UNITS, using the UTF-16 encoding. 
  https://docs.oracle.com/javase/specs/jls/se8/html/jls-3.html#jls-3.1
  """
  toBytes = [ pack('>H',c) for c in toUnsigned16bits ] #unsigned short to bytes
  if options.verbose>2:
    for c in toBytes: print(hexlify(c),end=',')
    print('')
  
  toUtf16be = [ codecs.decode(v,'UTF-16BE') for v in toBytes ] #from bytes to Utf16
  if options.verbose>2:
    for c in toUtf16be: print(repr(c),end='+')
    print('')
  """ 
   https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec.html
   \"Different PBE mechanisms may consume different bits of each password character. 
   For example, the PBE mechanism defined in PKCS #5 looks at only the low order 8 bits of each character, 
   whereas PKCS #12 looks at all 16 bits of each character. \"  
  """
  toUft8 = [ codecs.encode(t,'UTF-8') for t in toUtf16be ] # char must be encoded as UTF-8 first
  if options.verbose>2:
    for c in toUft8: print(hexlify(c),end='+')
    print('')

  return bytes( b''.join(toUft8) )

def chunkReader(f, chunkSize=CHUNK_SIZE):
  data = f.read(chunkSize)
  while data:
    yield data
    data = f.read(chunkSize)

def decrypt(encryptedIter, aesobj, chunkSize=CHUNK_SIZE):
  for encrypted in encryptedIter:
    yield aesobj.decrypt(encrypted)

def decompress(compressedDataIter, blockSize=CHUNK_SIZE):
  decompressobj = zlib.decompressobj()
  for compressedData in compressedDataIter:
    yield decompressobj.decompress(compressedData)
  yield decompressobj.flush()
  if not decompressobj.eof:
    raise RuntimeError("incomplete or truncated zlib stream")

parser = OptionParser()
parser.add_option("-p", "--pw", dest="password", help="password")
parser.add_option("-o", "--out", dest="output", default="backup.tar", help="output file")
parser.add_option("-v", "--verbose", type='int', dest="verbose", default=0, help="verbose mode")
parser.add_option("-b", "--backup", dest="backup", help="input file")
(options, args) = parser.parse_args()

if options.backup is None:
  print('-b argument is mandatory')
  exit()
  
f=open(options.backup,'rb')

if f.readline()[:-1]!=b'ANDROID BACKUP':
  print('not ANDROID BACKUP')
  exit()
  
#parse header   
header = dict()  
header['version'] = f.readline()[:-1]
header['compression'] = f.readline()[:-1]
header['encryption'] = f.readline()[:-1]
if options.verbose>1:
  print(header)

if header['encryption']==b'AES-256':
  if options.password is None:
    options.password = inputtty("Enter Password: ")
  password = options.password.encode('utf-8')
  #get PBKDF2 parameters to decrypt master key blob
  header['upSalt'] = unhexlify( f.readline()[:-1] )
  header['mkSumSalt'] = unhexlify( f.readline()[:-1] )
  header['round'] = int( f.readline()[:-1] )
  header['ukIV'] = unhexlify( f.readline()[:-1] )
  header['mkBlob'] = unhexlify( f.readline()[:-1] )
  if options.verbose>1:
    print('user password salt:', hexlify( header['upSalt']) )
    print('master key checksum salt:', hexlify(header['mkSumSalt']) )
    print('number of PBKDF2 rounds:', header['round'] )
    print('user key IV:', hexlify(header['ukIV']) )
    print('master key blob:', hexlify(header['mkBlob']) )
  # generate AES key from password and salt
  key = PBKDF2(password, header['upSalt'], 32, header['round']) #default algo is sha1
  # decrypt master key blob 
  decrypted = AES.new(key, AES.MODE_CBC, header['ukIV']).decrypt( header['mkBlob'] )
  # parse decrypted blob
  Niv = decrypted[0] # IV length
  iv = decrypted[1:1+Niv] # AES CBC IV
  Nmk = ord( decrypted[1+Niv:1+Niv+1] ) # master key length
  mk = decrypted[1+Niv+1:1+Niv+1+Nmk] # AES 256 key
  Nck = ord( decrypted[1+Niv+1+Nmk:1+Niv+1+Nmk+1] ) # check value length
  ck = decrypted[1+Niv+1+Nmk+1:1+Niv+1+Nmk+1+Nck] # check value
  if options.verbose>1:
    print('IV length:',Niv)
    print('IV:',hexlify(iv))
    print('master key length:',Nmk)
    print('master key:',hexlify(mk))
    print('check value length:',Nck)
    print('check value:',hexlify(ck))
    
  #verify password
  toBytes2 = masterKeyJavaConversion( bytearray(mk) ) # consider data as bytes, not str
  if options.verbose>1:
    print('PBKDF2 secret value for password verification is: ', end='')
    print( hexlify(toBytes2) )
  ck2 = PBKDF2( toBytes2, header['mkSumSalt'], Nck, header['round'] ) 
  if ck2!=ck:
    print( 'computed ck:', hexlify(ck2), 'is different than embedded ck:', hexlify(ck) )
  else:
    print('password verification is OK')  
  
  # decryption using master key and iv
  compressedIter = decrypt(chunkReader(f), AES.new(mk, AES.MODE_CBC, iv))

elif header['encryption']=='none':
  print('no encryption') 
  compressedIter = chunkReader(f)
else:
  print('unknown encryption')
  exit()
  
if options.verbose:
  print('decompression... ', end='')
# decompression (zlib stream)
out = open(options.output,'wb')
print('writing backup as .tar ... ', end='', flush=True)
for decData in decompress(compressedIter):
  out.write(decData)
print(f'OK. Filename is \'{options.output}\', {out.tell()} bytes written.')
out.close()

f.close()
