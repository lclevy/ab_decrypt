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
import codecs
import ctypes
import zlib
from binascii import unhexlify, hexlify
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from optparse import OptionParser
from struct import pack

VERBOSITY=0
CHUNK_SIZE=128*1024

def dprint(*args, **kwargs):
  kwargs.setdefault('file', sys.stderr)
  kwargs.setdefault('flush', True)
  print(*args, **kwargs)

def inputtty(prompt=""):
  if platform.system() == "Windows":
    return input(prompt)
  with open('/dev/tty', 'rb') as ftty:
    if prompt:
      with open('/dev/tty', 'wb') as fwtty:
        fwtty.write(prompt.encode('utf8'))
        fwtty.flush()
    return ftty.readline().decode('utf8').rstrip("\n")

def readHeader(f):
  header = dict()
  header['version'] = f.readline()[:-1]
  header['compression'] = f.readline()[:-1]
  header['encryption'] = f.readline()[:-1]

  if header['encryption']==b'none':
    pass
  elif header['encryption']==b'AES-256':
    #get PBKDF2 parameters to decrypt master key blob
    header['upSalt'] = unhexlify( f.readline()[:-1] )
    header['mkSumSalt'] = unhexlify( f.readline()[:-1] )
    header['round'] = int( f.readline()[:-1] )
    header['ukIV'] = unhexlify( f.readline()[:-1] )
    header['mkBlob'] = unhexlify( f.readline()[:-1] )
    if VERBOSITY>1:
      dprint('user password salt:', hexlify( header['upSalt']) )
      dprint('master key checksum salt:', hexlify(header['mkSumSalt']) )
      dprint('number of PBKDF2 rounds:', header['round'] )
      dprint('user key IV:', hexlify(header['ukIV']) )
      dprint('master key blob:', hexlify(header['mkBlob']) )
  else:
    raise RuntimeError(f"Unsupported encryption scheme: {header['encryption']}")
  return header

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
  if VERBOSITY>2: dprint(toSigned)
  # Narrowing Primitive Conversion : https://docs.oracle.com/javase/specs/jls/se8/html/jls-5.html#jls-5.1.3
  toUnsigned16bits = [ ctypes.c_ushort(x).value & 0xffff for x in toSigned ]
  if VERBOSITY>2:
    dprint(('{:x} '*len(toUnsigned16bits)).format(*toUnsigned16bits))
  """ 
  The Java programming language represents text in sequences of 16-bit code UNITS, using the UTF-16 encoding. 
  https://docs.oracle.com/javase/specs/jls/se8/html/jls-3.html#jls-3.1
  """
  toBytes = pack(f'>{len(toUnsigned16bits)}H', *toUnsigned16bits ) #unsigned short to bytes
  if VERBOSITY>2:
    dprint(hexlify(toBytes, sep=',').decode('ascii'))
  
  toUtf16be = codecs.decode(toBytes,'UTF-16BE') #from bytes to Utf16
  if VERBOSITY>2:
    dprint(hexlify(toUtf16be.encode('UTF-16BE'), sep='+').decode('ascii'))
  """ 
   https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec.html
   \"Different PBE mechanisms may consume different bits of each password character. 
   For example, the PBE mechanism defined in PKCS #5 looks at only the low order 8 bits of each character, 
   whereas PKCS #12 looks at all 16 bits of each character. \"  
  """
  toUft8 = codecs.encode(toUtf16be,'UTF-8') # char must be encoded as UTF-8 first
  if VERBOSITY>2:
    dprint(hexlify(toUft8, sep='+').decode('ascii'))

  return toUft8

def getAESDecrypter(header, password):
  assert header['encryption']==b'AES-256', f"Not using AES decryption: {header['encryption']}"
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
  if VERBOSITY>1:
    dprint('IV length:',Niv)
    dprint('IV:',hexlify(iv))
    dprint('master key length:',Nmk)
    dprint('master key:',hexlify(mk))
    dprint('check value length:',Nck)
    dprint('check value:',hexlify(ck))
  
  #verify password
  toBytes2 = masterKeyJavaConversion( bytearray(mk) ) # consider data as bytes, not str
  if VERBOSITY>1:
    dprint('PBKDF2 secret value for password verification is: ', end='')
    dprint( hexlify(toBytes2) )
  ck2 = PBKDF2( toBytes2, header['mkSumSalt'], Nck, header['round'] )
  if ck2!=ck:
    dprint( 'computed ck:', hexlify(ck2), 'is different than embedded ck:', hexlify(ck) )
  else:
    dprint('password verification is OK')
  # decryption using master key and iv
  return AES.new(mk, AES.MODE_CBC, iv)

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

def ab2tar(f, fout, password=None):
  if f.readline()[:-1]!=b'ANDROID BACKUP':
    dprint('not ANDROID BACKUP')
    return False

  #parse header
  header = readHeader(f)
  if VERBOSITY>1:
    dprint(header)

  if header['encryption']==b'AES-256':
    if password is None:
      password = inputtty("Enter Password: ")
    password = password.encode('utf-8')
    compressedIter = decrypt(chunkReader(f), getAESDecrypter(header, password))
  elif header['encryption']==b'none':
    dprint('no encryption')
    compressedIter = chunkReader(f)
  else:
    dprint('unknown encryption')
    return False

  # decompression (zlib stream)
  dprint('writing backup as .tar ... ', end='', flush=True)
  for decData in decompress(compressedIter):
    fout.write(decData)
  dprint(f'OK. Filename is \'{fout.name}\', {fout.tell()} bytes written.')
  return True

def main(argv):
  global VERBOSITY
  parser = OptionParser()
  parser.add_option("-p", "--pw", dest="password", help="password")
  parser.add_option("-o", "--out", dest="output", default="-", help="output file")
  parser.add_option("-v", "--verbose", type='int', dest="verbose", default=0, help="verbose mode")
  parser.add_option("-b", "--backup", dest="backup", help="input file")
  (options, args) = parser.parse_args()

  VERBOSITY = options.verbose
  if options.backup is None:
    dprint('-b argument is mandatory')
    return 1

  if options.output == '-':
    fout = sys.stdout.buffer
  else:
    fout = open(options.output,'wb')

  with open(options.backup,'rb') as abfile:
    return int(not ab2tar(abfile, fout, options.password))
  fout.close()

if __name__ == "__main__":
  exit(main(sys.argv[1:]))
