__author__ = "Dell-Ray Sackett"
__version__ = "0.1"
import pickle
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import base64
import binascii


class Message:
    """
    This is a class to hold an encrypted message. It is specifically 
    designed to be pickeled and stored. Nothing more. Although I guess it 
    could have some use in networking?
    """
    
    def __init__(self, publicKey, symmetricKey, signature, message):
        """
        Initialize the object.
        
        Keyword Arguments:
        publicKey -- The public key of the sending party. Should be a x509 DER
            sequence that can be directly imported by pyCrypto.
        symmetricKey -- The asymmetrically encrypted symmetric key for AES256
            encryption.
        signature -- Message .
        message -- The message encrypted.
        
        """
        self._publicKey = publicKey
        self._symmetricKey = symmetricKey
        self._signature = signature
        self._message = message
    
    """
    There is no real reason to only get 1 of these values. So I am only
    providing a method for returning everything.
    """
    def getMessage(self):
        """Return a list containing all the message information."""
        
        return [self._publicKey, self._symmetricKey, self._signature, self._message]
    
    #Pickle and Unpickle
    def dumpMessage(self):
        """Pickle the message and return it."""
        
        return pickle.dumps(self)

    @staticmethod
    def loadMessage(message):
        """Unpickle a message string and return the object"""
        
        return pickle.loads(message)
        

class CryptoHelper:
    """
    This class will do the encryption and decryption of a message object.
    It will be almost completely static hah!
    """
    
    
    """
    I took pad and unpad from a stack exchange post.
    http://stackoverflow.com/a/12525165
    """
    #Define the symmetric block size as a static variable.
    BS = 16
    
    @staticmethod
    def pad(s):
        """
        Takes string s and returns it padded to blocksize CryptoHelper.BS.
        """
        
        return s + (CryptoHelper.BS - len(s) % CryptoHelper.BS) * chr(
            CryptoHelper.BS - len(s) % CryptoHelper.BS)
    
    @staticmethod
    def unpad(s):
        """
        Takes padded string s and returns it sans padding.
        """
        
        return s[:-ord(s[len(s)-1:])]
    
    
    #Static Methods
    @staticmethod
    def generateKeys(filename, passphrase, modulus=2048):
        """
        Generates a RSA keypair and returns it.
        
        Manditory Arguments:
        filename -- The name of the file to save the key to.
        passphrase -- The passphrase for the key. If you think your key 
            doesn't need a key. You are dumb.
        
        Optional Arguments:
        modulus -- The size modulus to use. (String, default=2048)
        """
        
        key = RSA.generate(modulus)
        
        if passphrase == "" or passphrase == None:
            raise ValueError("Passphrase cannot be empty")
        
        if filename[len(filename)-4:] != ".pem":
            filename += ".pem"
        try:
            keyfile = open(filename, "w")
            pubkeyFile = open(filename[:len(filename)-4] + 
                "publiconly.pem", "w")
            
        except Exception as e:
            raise e
        keyfile.write(key.exportKey(format="PEM", passphrase=passphrase))
        pubkeyFile.write(key.exportKey(format="PEM", pkcs=8))
        keyfile.close()
        pubkeyFile.close()
        return key

    @staticmethod
    def importKeys(filename, passphrase):
        """
        Import a key from file and return a RSA key object
        
        Manditory Arguments:
        filename -- The filename of the key to import.
        passphrase -- The passphrase for your key
        """
        
        try:
            keyfile = open(filename, "r")
        except Exception as e:
            raise e
        
        return RSA.importKey(keyfile.read(), passphrase)
    
    @staticmethod
    def getPublicKey(keyPair):
        """Return the PEM encoded public key"""
        
        return keyPair.publickey().exportKey()
        
    @staticmethod
    def symmetricEncrypt(plaintext):
        """
        Takes a string and encrypts it. Returning a tuple with the IV, 
        the symmetric key (plaintext) and the encrypted 
        string. The IV and the ciphertext will be concatenated together with 
        the IV in front.
        
        Manditory Arguments:
        plaintext -- A string to be encrypted.
        """
        
        paddedPlaintext = CryptoHelper.pad(plaintext)
        IV = Random.new().read(AES.block_size)
        key = SHA256.new(Random.new().read(1024)).digest()
        cryptor = AES.new(key, AES.MODE_CBC, IV)
        return (key, base64.b64encode( 
            IV + cryptor.encrypt(paddedPlaintext)))
        
    @staticmethod
    def symmetricDecrypt(key, ciphertext):
        """
        Takes a key and base64 encoded ciphertext with an IV concatenated at 
        the beginning and returns a plaintext string.
        """
        
        decodedCiphertext = base64.b64decode(ciphertext)
        IV = decodedCiphertext[:16]
        cryptor = AES.new(key, AES.MODE_CBC, IV)
        return CryptoHelper.unpad(cryptor.decrypt(decodedCiphertext[16:]))
    
    @staticmethod
    def encryptMessage(message, encryptionKeyFilename, signingKeyFilename, 
            signingKeyPassphrase):
        """
        Takes a String message and encrypts it with the publickey from
        the RSA publickey in the file from encryptionKeyFilename. Also signs
        the message with the RSA keypair from file signingKeyFilename. Returns
        a Message object.
        
        Manditory Arguments:
        message -- A message in the form of a string.
        encryptionKeyFilename -- Filename of the publickey to use for 
            encryption as a String.
        signingKeyFilename -- Filename of the RSA keypair to use for
            signing the message as a string
        signingKeyPassphrase -- The passphrase to the singing keypair.
        """
        
        encKey = CryptoHelper.importKeys(encryptionKeyFilename, "")
        sigKey = CryptoHelper.importKeys(signingKeyFilename, 
            signingKeyPassphrase)
        myHash = SHA256.new()
        myHash.update(message)
        cipheredMessage = CryptoHelper.symmetricEncrypt(message)
        messageSig = base64.b64encode(str(sigKey.sign(myHash.digest(), "")[0]))
        symmetricKey = base64.b64encode(encKey.encrypt(cipheredMessage[0], 32)[0])
        pubKey = CryptoHelper.getPublicKey(sigKey)
        
        return Message(pubKey, symmetricKey, messageSig, cipheredMessage[1])
        
    @staticmethod
    def decryptMessage(messageObject, decryptionKeyFilename, 
        decryptionKeyPassphrase):
        """
        Takes a message Object and a string containing the filename of the
        decryption keypair. Decrypts and verifies the message. If the message
        is verified returns a string containing the plaintext message.
        
        Manditory Arguments:
        
        messageObject -- A Message object containing the encrypted message.
            With senders publicKey and a signature.
        deryptionKeyFilename -- String containing the filename of the RSA
            keypair to be used for decryption.
        decryptionKeyPassphrase -- String containing the passphrase for 
            decrypting the decryption key.
        """
        
        try:
            decryptKey = CryptoHelper.importKeys(decryptionKeyFilename, 
                decryptionKeyPassphrase)
        except Exception as e:
            raise e
        
        #A list with [publicKey, signature, encMessage]
        expandedMessage = messageObject.getMessage()
        sigKey = RSA.importKey(expandedMessage[0])
        symmetricKey = decryptKey.decrypt(base64.b64decode(expandedMessage[1]))
        plainText = CryptoHelper.symmetricDecrypt(symmetricKey, expandedMessage[3])
        messageHash = SHA256.new(plainText).digest()
        signature = (long(base64.b64decode(expandedMessage[2])),)
        if not sigKey.verify(messageHash, signature):
            raise ValueError("The message could not be verified")
        else:
            return plainText