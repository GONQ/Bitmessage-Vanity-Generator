import sys, os, base64, hashlib, time
from struct import *
from pyelliptic.openssl import OpenSSL
import ctypes
from pyelliptic import arithmetic
from binascii import hexlify
import threading

def encodeVarint(integer):
    if integer < 0:
        print 'varint cannot be < 0'
        raise SystemExit
    if integer < 253:
        return pack('>B',integer)
    if integer >= 253 and integer < 65536:
        return pack('>B',253) + pack('>H',integer)
    if integer >= 65536 and integer < 4294967296:
        return pack('>B',254) + pack('>I',integer)
    if integer >= 4294967296 and integer < 18446744073709551616:
        return pack('>B',255) + pack('>Q',integer)
    if integer >= 18446744073709551616:
        print 'varint cannot be >= 18446744073709551616'
        raise SystemExit
    
def encodeAddress(version,stream,ripe):
    if version >= 2 and version < 4:
        if len(ripe) != 20:
            raise Exception("Programming error in encodeAddress: The length of a given ripe hash was not 20.")
        if ripe[:2] == '\x00\x00':
            ripe = ripe[2:]
        elif ripe[:1] == '\x00':
            ripe = ripe[1:]
    elif version == 4:
        if len(ripe) != 20:
            raise Exception("Programming error in encodeAddress: The length of a given ripe hash was not 20.")
        ripe = ripe.lstrip('\x00')

    verVar = encodeVarint(version)
    strVar = encodeVarint(stream)
    storedBinaryData = encodeVarint(version) + encodeVarint(stream) + ripe
    
    # Generate the checksum
    sha = hashlib.new('sha512')
    sha.update(storedBinaryData)
    currentHash = sha.digest()
    sha = hashlib.new('sha512')
    sha.update(currentHash)
    checksum = sha.digest()[0:4]

    asInt = int(hexlify(storedBinaryData) + hexlify(checksum),16)
    return 'BM-'+ encodeBase58(asInt)

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def encodeBase58(num, alphabet=ALPHABET):
    """Encode a number in Base X

    `num`: The number to encode
    `alphabet`: The alphabet to use for encoding
    """
    if (num == 0):
        return alphabet[0]
    arr = []
    base = len(alphabet)
    while num:
        rem = num % base
        #print 'num is:', num
        num = num // base
        arr.append(alphabet[rem])
    arr.reverse()
    return ''.join(arr)

#Does an EC point multiplication; turns a private key into a public key.
def pointMult(secret):
    #ctx = OpenSSL.BN_CTX_new() #This value proved to cause Seg Faults on Linux. It turns out that it really didn't speed up EC_POINT_mul anyway.
    k = OpenSSL.EC_KEY_new_by_curve_name(OpenSSL.get_curve('secp256k1'))
    priv_key = OpenSSL.BN_bin2bn(secret, 32, 0)
    group = OpenSSL.EC_KEY_get0_group(k)
    pub_key = OpenSSL.EC_POINT_new(group)

    OpenSSL.EC_POINT_mul(group, pub_key, priv_key, None, None, None)
    OpenSSL.EC_KEY_set_private_key(k, priv_key)
    OpenSSL.EC_KEY_set_public_key(k, pub_key)
    #print 'priv_key',priv_key
    #print 'pub_key',pub_key

    size = OpenSSL.i2o_ECPublicKey(k, 0)
    mb = ctypes.create_string_buffer(size)
    OpenSSL.i2o_ECPublicKey(k, ctypes.byref(ctypes.pointer(mb)))
    #print 'mb.raw', mb.raw.encode('hex'), 'length:', len(mb.raw)
    #print 'mb.raw', mb.raw, 'length:', len(mb.raw)

    OpenSSL.EC_POINT_free(pub_key)
    #OpenSSL.BN_CTX_free(ctx)
    OpenSSL.BN_free(priv_key)
    OpenSSL.EC_KEY_free(k)
    return mb.raw

found_one = False
def thread_main():
	global found_one
	prefix = args[0]
	deterministicNonce = 0
	startTime = time.time()
	while found_one != True:
		#We generate addresses based off of a secure random string plus an integer nonce.
		deterministicNall = base64.b64encode(os.urandom(options.bytes))
		address=""
		while found_one != True:
		    #This next section is a little bit strange. We're going to generate keys over and over until we
		    #find one that has a RIPEMD hash that starts with either \x00 or \x00\x00. Then when we pack them
		    #into a Bitmessage address, we won't store the \x00 or \x00\x00 bytes thus making the address shorter.
		    signingKeyNonce = 0
		    encryptionKeyNonce = 1
		    numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix = 0
		    deterministicPassphrase = deterministicNall + str(deterministicNonce)
		    while found_one != True: #find a keypair pair whose hash starts with \x00
		        numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix += 1
		        potentialPrivSigningKey = hashlib.sha512(deterministicPassphrase + encodeVarint(signingKeyNonce)).digest()[:32]
		        potentialPrivEncryptionKey = hashlib.sha512(deterministicPassphrase + encodeVarint(encryptionKeyNonce)).digest()[:32]
		        potentialPubSigningKey = pointMult(potentialPrivSigningKey)
		        potentialPubEncryptionKey = pointMult(potentialPrivEncryptionKey)
		        signingKeyNonce += 2
		        encryptionKeyNonce += 2
		        ripe = hashlib.new('ripemd160')
		        sha = hashlib.new('sha512')
		        sha.update(potentialPubSigningKey+potentialPubEncryptionKey)
		        ripe.update(sha.digest())
		        #print 'potential ripe.digest', ripe.digest().encode('hex')
		        if options.eighteenByteRipe:
		            if ripe.digest()[:2] == '\x00\x00':
		                break
		        else:
		            if ripe.digest()[:1] == '\x00':
		                break

		    address = encodeAddress(4,options.streamNumber,ripe.digest())

                    privSigningKey = '\x80' + potentialPrivSigningKey
                    checksum = hashlib.sha256(hashlib.sha256(
                        privSigningKey).digest()).digest()[0:4]
                    privSigningKeyWIF = arithmetic.changebase(
                        privSigningKey + checksum, 256, 58)

                    privEncryptionKey = '\x80' + potentialPrivEncryptionKey
                    checksum = hashlib.sha256(hashlib.sha256(
                        privEncryptionKey).digest()).digest()[0:4]
                    privEncryptionKeyWIF = arithmetic.changebase(
                        privEncryptionKey + checksum, 256, 58)

		    deterministicNonce += 1
		    if options.insensitive:
		        if (address[:len(prefix)].lower() == prefix.lower()):
		            print "[" + address+ "]"
		            print "privsigningkey = " + privSigningKeyWIF
		            print "privencryptionkey = " + privEncryptionKeyWIF
		            found_one = True
		            if not options.quiet:
		            	print "Generated " + str(deterministicNonce) + " addresses in " + str(time.time() - startTime) + " seconds."
		            break
		    else:
		        if (address[:len(prefix)] == prefix):
		            print "[" + address+ "]"
		            print "privsigningkey = " + privSigningKeyWIF
		            print "privencryptionkey = " + privEncryptionKeyWIF
		            found_one = True
		            if not options.quiet:
		            	print "Generated " + str(deterministicNonce) + " addresses in " + str(time.time() - startTime) + " seconds."
		            break

		if not options.keep:
		    break

from optparse import OptionParser
usage = "usage: %prog [options] prefix"
parser = OptionParser(usage=usage)
parser.add_option("-i", "--insensitive",
                  action="store_true", dest="insensitive", default=False,
                  help="Case-insensitive prefix search")
parser.add_option("-e", "--short",
                  action="store_true", dest="eighteenByteRipe", default=False,
                  help="Require 'generate shorter address' to be checked")
parser.add_option("-s", "--stream",
                  dest="streamNumber", default=1, type="int",
                  help="Use this stream number (default 1)")
parser.add_option("-k", "--continue",
                  action="store_true", dest="keep", default=False,
                  help="Keep address and continue search after finding a match")
parser.add_option("-b", "--bytes",
                  dest="bytes", default=63, type="int",
                  help="Number of secure random bytes to base the passphrase on (default 63)")
parser.add_option("-t", "--threads",
                  dest="threadCount", default=1, type="int",
                  help="Number of threads to use (default 1)")
parser.add_option("-q", "--quiet",
                  action="store_true", dest="quiet", default=False,
                  help="Only print addresses and privkeys")

(options, args) = parser.parse_args()

if len(args) == 0:
    parser.print_help()
    sys.exit()
    
if options.streamNumber == 1:
    if args[0].startswith("BM-2c") == False:
        print "Illegal Bitmessage address prefix.  Must start with BM-2c"
        sys.exit()

    if len(args[0]) > 5 and args[0][5] not in 'STUVWX':
        print "Illegal Bitmessage address prefix.  Character after BM-2c must be one of 'S','T','U','V','W','X'"
        sys.exit()
        
    if len(args[0]) > 6 and args[0][6:] in '01':
        print "Illegal Bitmessage address prefix.  Digits 2-9 are allowed but not 0 and 1"
        sys.exit()
else:
    print "Non-standard stream number specified.  bmgen may hang or produce unusable results."
    
threads = []
for i in range(0,options.threadCount):
    t = threading.Thread(target=thread_main,)
    threads.append(t)
    t.start()

# wait for all the threads to complete
for thread in threads:
    thread.join()

