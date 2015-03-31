#!/usr/bin/python
__author__ = "Dell-Ray Sackett"
__version__ = "0.6"
import argparse

from PIL import Image
import numpy

from message import Message
from message import CryptoHelper


class Steganographer(object):
    """
    An object for performing Steganography on an image.
    """

    def __init__(self, **kwargs):
        """
        Initialize a Steganography object

        Keyword Arguments:
        inputFile -- The filename of the image you wish to embed information information.
        outputFile -- The filename of the image that will have your information in it.
        """

        self._inputFile = ""
        self._outputFile = ""
        self.__imageData = numpy.empty((1, 1, 1))
        self.__colorMode = ""
        self.__colorSize = 0
        self.__imageSize = (0, 0)
        self.__maxBitsStorable = 0

        if kwargs:
            for arg in kwargs:
                if arg is "inputFile":
                    self._inputFile = kwargs[arg]
                elif arg is "outputFile":
                    self._outputFile = kwargs[arg]



    #Static Methods
    @staticmethod
    def intToBinList(number):
        """
        Return the least significant 32 bits of a number as a list.

        Manditory Arguments:
        number -- The number you would like returned as a list.
        """

        listValue = []
        for i in reversed(range(32)):
            """
            Iterate through the last 32 bits of the number passed. I sigle out
            each bit by bitshifting the number 1 (essentially a bitmask here)
            left by the current index then bitwise anding that against the
            original number. That gives me the value of that position then I
            shift it back by the index to make sure that the bit only occupies
            the 1 bit. If you don't do that last part then python with
            interpret it as whatever value that bitplace holds. ie if it was
            the 8 bit and it was set then you will get 8 instead of 1.
            """
            listValue += [((1 << i) & number) >> i]
        return listValue

    @staticmethod
    def binListToInt(binList):
        """
        Returns the integer value of a binary list.

        Manditory Arguments:
        binList -- A list of 1s and 0s to be assembled back into an integer.
        """

        intValue = 0
        for i in range(32):
            """
            This is pretty simple. You just get the value from the current
            index. Which should only be a 1 or a 0. Then shift it left by the
            index. Lastly you add the number created by the shift to the
            current value.
            """
            intValue += binList[31 - i] << i
        return intValue

    @staticmethod
    def charToBinList(char):
        """
        Return a list of 1s and 0s representing the binary of a character.

        Manditory Arguments:
        char -- A character to be broken down into a list.
        """

        intValue = ord(char)
        listValue = []

        for i in reversed(range(8)):
            listValue += [((1 << i) & intValue) >> i]

        return listValue

    @staticmethod
    def binListToChar(binList):
        """
        Take a binary List and turn it back into a char.

        Manditory Arguments:
        binList -- A list of 1s and 0s to be back into a char.
        """
        intValue = 0

        for i in range(8):
            intValue += binList[7 - i] << i
        return chr(intValue)

    @staticmethod
    def messageToBinList(message):
        """
        Takes a message and turns it into a binary list

        Manditory Arguments:
        message -- A string to be broken down into a list of binary values.
        """

        listValue = []
        for character in message:
            listValue += Steganographer.charToBinList(character)
        return listValue

    @staticmethod
    def binListToMessage(binList):
        """
        This turns a binary list back into a message.

        Manditory Arguments:
        binList -- A list of 1s and 0s to be converted back into a string.
            Must be divisable by 8.
        """

        if (len(binList) % 8) is not 0:
            raise ValueError("The input list is required to be evenly divisable by 8")

        listTmp = []
        bitCounter = 0
        message = ""
        for value in range(0, len(binList)):
            listTmp.append(binList[value])
            if bitCounter == 7:
                message += Steganographer.binListToChar( listTmp )
                listTmp = []
                bitCounter = -1
            bitCounter += 1
        return message

    # I "Borrowed" this wholesale from stack exchange
    @staticmethod
    def set_bit(v, index, x):
        """
        Set the index:th bit of v to x, and return the new value.

        Manditory Arguments:
        v -- A variable in which a bit is to be changed.
        index -- The index of the bit to change.
        x -- The value to change index in variable v to.
        """
        mask = 1 << index
        v &= ~mask
        if x:
            v |= mask
        return v

    @staticmethod
    def compare_pixels(imageA, imageB, pixels=512):
        """
        Compare the specified amount of pixel data of the two pictures given.
        """
        print("Reading " + str(pixels) + " pixels from " + imageA + " and " + imageB + ".")
        try:
            __oim = Image.open(imageA)
            __nim = Image.open(imageB)
        except IOError:
            print("Something went wrong trying to open the pictures")
            exit(1)

        __oimd = numpy.asarray(__oim)
        __nimd = numpy.asarray(__nim)

        if not (__nim.size[0] == __oim.size[0] and __nim.size[1] == __oim.size[1]):
            print("The images need to be the same size!")
            exit(1)

        __pixelIndex = 0
        try:
            for heightIndex in range(0, __oim.size[1]):
                for widthIndex in range(0, __oim.size[0]):
                    if __pixelIndex >= pixels:
                        raise Exception("Done!")
                    else:
                        print(str(__pixelIndex) + ": " +
                              str(__oimd[widthIndex][heightIndex]) + " --> " +
                              str(__nimd[widthIndex][heightIndex]))
                        __pixelIndex += 1
        except Exception:
            pass
        __oim.close()
        __nim.close()

    @staticmethod
    def read_message_from_file(filename):
        """
        Return the contents of a file as a string.

        Manditory Arguments:
        filename - The filename to read the message from.
        """

        try:
            # This might not be a great idea but we are going to try to read the entire file into a string all at once.
            fd = open(filename, 'r')
            message = fd.read()
            fd.close()
        except IOError as e:
            raise e
        return message

    @staticmethod
    def writemessagetofile(message, filename):
        """
        Write a message, as a string, to a file.

        Manditory Arguments:
        message - The string to be written to the file.
        filename - The name of the file to write the string to.
        """

        try:
            fd = open(filename, "w")
            fd.write(message)
            fd.close()
        except Exception as e:
            raise e


    # Getters/Setters

    def getInputImageFile(self):
        """Return the filename of the input image."""
        return self._inputFile

    def getOutputImageFile(self):
        """Return the filename of the encoded image."""
        return self._outputFile

    # Instance Methods
    def initializeImageData(self):
        """
        This prepares the class for image manipulation.
        """
        if self._inputFile == "":
            raise ValueError("You must supply an input file name to encode "
                + "decode, or compare pixels.")
        try:
            __imageIn = Image.open(self._inputFile)
        except IOError as e:
            raise e
        except Exception as e:
            raise Exception("The following unexpect Exception was "
                + "encountered while trying to open the input image.\n"
                + str(e))
        # Without the numpy.copy() the data would be read only
        self.__imageData = numpy.copy(numpy.asarray(__imageIn))
        self.__colorMode = __imageIn.mode
        self.__imageSize = __imageIn.size
        __imageIn.close()

        # Set color size
        if self.__colorMode == "RGB":
            self.__colorSize = 3
        elif self.__colorMode == "RGBA":
            # Don't encode to the alpha value
            self.__colorSize = 3
        elif self.__colorMode == "CMYK":
            self.__colorSize = 4
        elif self.__colorMode == "YCbCr":
            self.__colorSize = 4
        else:
            raise ValueError("The input image " + self._inputFile +
                             " cntains an unsupported color model.")

        # Calculate the maximum number of bits we'll be able to store.
        self.__maxBitsStorable = self.__imageSize[0] * self.__imageSize[1]
        self.__maxBitsStorable *= self.__colorSize

    def saveOutputImage(self):
        """Save the stored image data to file"""

        __imageOut = Image.fromarray(self.__imageData)
        try:
            __imageOut.save(self._outputFile, 'PNG', compress_level=0)
        except IOError as e:
            raise e
        except Exception as e:
            raise Exception("The encoding function encountered the following "
                + "unhandled exception while attempting to save the image.\n"
                + str(e))
        # Close the image. I don't know if this is explicitly necessary but feels right. Ya know?
        __imageOut.close()

        # Sing songs of our success
        print("Image encode and saved as " + self._outputFile)

    def encodeImage(self, message):
        """
        Enocde a message into a picture.
        """

        __message = message
        # Error Handling
        if self._outputFile == "":
            raise ValueError("No output filename specified. Please specify"
                + " a filename and call encodeImage() again.")
        if self.__imageData.shape == (1, 1, 1):
            """Uninitialized image or smallest image ever."""
            try:
                self.initializeImageData()
            except Exception as e:
                raise e
        if __message == "":
            raise ValueError("Message not set. Please set message and"
                + " call encodeImage() again.")

        __bitSequence = Steganographer.intToBinList(len(__message))
        __bitSequence += Steganographer.messageToBinList(__message)

        # Pad the message
        __padSize = self.__colorSize - ( len(__bitSequence) % self.__colorSize)
        for i in range(0, __padSize):
            __bitSequence += [0]

        if len(__bitSequence) >= self.__maxBitsStorable:
            raise ValueError("The message or message file provided was too "
                + "to be encoded onto image " + self._inputFile + ".")

        """
        I am pretty sure this formatting is more levels than I can count
        against PEP8. I am going to leave it like this though because I think
        it is easier to read. I feel like Clark, Johnny, and Joe would likely
        agree.
        """
        __bitIndex = 0
        __bitList = [0, 0, 0]
        try:
            for heightIndex in range(0, self.__imageSize[0]):

                for widthIndex in range(0, self.__imageSize[1]):

                    for colorIndex in range(0, self.__colorSize):

                        if __bitIndex >= len(__bitSequence):
                            raise Exception("Done!")
                        else:
                            __bitList[colorIndex] = Steganographer.set_bit(
                                self.__imageData[widthIndex][heightIndex][colorIndex],
                                0,
                                __bitSequence[__bitIndex])
                            __bitIndex += 1

                    self.__imageData[widthIndex][heightIndex] = __bitList
                    __bitList = [0, 0, 0]
        except Exception as e:
            pass
        try:
            self.saveOutputImage()
        except Exception as e:
            raise e

    def decodeImage(self):

        if self.__imageData.shape == (1, 1, 1):
            try:
                self.initializeImageData()
            except Exception as e:
                raise e

        #create a list to get the number of bits in the message
        __lenList = []

        #This shit...
        #There are 32 bits (Intiger presumably, Python is a little willy-nilly
        # on primative types) of length data at the beginning of the encoding
        # 32/3 = 10 with 2 bits left over. So I need the first 10 pixels worth
        # of LSBs and the Red and Green LSB out of the 11th pixel. So, I
        # iterate through all 11 and on the 11th pixel I store normally until
        # I hit the Blue value, then I just pass which ends both loops.
        try:
            __bitIndex = 0
            for heightIndex in range(0, self.__imageSize[0]):
                for widthIndex in range(0, self.__imageSize[1]):
                    for colorIndex in range(0, self.__colorSize):
                        if __bitIndex >= 32:
                            raise Exception("Done!")
                        else:
                            __lenList.append(self.__imageData[widthIndex][heightIndex][colorIndex] & 1)
                            __bitIndex += 1
        except Exception as e:
            pass
        #Now we know how many bits to expect so we convert that back into an Int and store it for later
        __messageLength = Steganographer.binListToInt(__lenList)

        #I found it was easier on me to just store the entire with the length data at first.
        # Also, to make the encoding loop easier I padded the end of it so it would be evenly
        # divisable by the number of colors in the image. Here I will just grab everything
        # out of the picture all at once and store it in total list. Then I will use the message
        # length information to iterate through only the message bits so I don't have to do any
        # silly shit in the inner for loop here to weed out the length/padding data.
        __totalList = []

        #I stored the message length in characters which are 8 bits a piece. However, I work mostly
        # in number of bits instead of bytes so I
        # have to convert it off of the bat.
        __messageBitLength = __messageLength * 8

        #Iterate through all of the bits that I believe were encoded onto the image.
        try:
            __bitsProcessed = 0
            for heightIndex in range(0, self.__imageSize[0]):

                for widthIndex in range( 0, self.__imageSize[1]):

                    for colorIndex in range( 0, self.__colorSize):

                        if __bitsProcessed >= (__messageBitLength + 32):
                            raise Exception("Done!")
                        else:
                            __totalList.append(
                                self.__imageData[widthIndex][heightIndex][colorIndex] & 1)
                            __bitsProcessed += 1

        except Exception as e:
            pass

        #create a list to store the message bitsequence
        __messageList = []

        print(len(__totalList))
        #Iterate from the end to the end of the message data. So the message will always start
        # at the 33nd (decimal value 32) bit because the length data is 32 bits long. Then if the
        # message is x long we want to count from 32 to x + 32 since the message data will essentially
        # be offset in the picture by 32 bits. This also leaves out the padding data because we are
        # only iterating to the end of the message data exactly so the padding will be left out of the
        # message. That is good because the bitStringToMessage function will return and error string
        # if the message data isn't cleanly divisable by 8. Which it wouldn't be with the padding.
        for index in range(32, __messageBitLength + 32):
            __messageList.append(__totalList[ index ])

        #Convert the message from a list of binary values do a string
        __message = Steganographer.binListToMessage(__messageList)

        return __message

    def encodeimagefromfile(self, filename):
        """
        This function will open a file, read the contents, then pass the
        contents as a message to encodeImage.

        Manditory Arguments:
        filename - The name of the file containing the message.
        """

        try:
            __message = Steganographer.readmessagefromfile(filename)
        except IOError:
            print("The file " + filename + " could not be read.")
            return

        self.encodeImage(__message)

    def decodeimagetofile(self, filename):
        """
        This function will decode the message in an image and dump the
        message into a file.

        Manditory Arguments:
        filename - The name of the file to save the message to.
        """

        __message = self.decodeImage()
        try:
            Steganographer.writemessagetofile(__message, filename)
        except IOError:
            print("There was a problem opening the file " + filename +
                ".")
            return
        print("Message saved to " + filename + ".")

class EncryptedSteganographer(Steganographer):
    """
    This subclass of the Steganographer class adds encryption to the message.
    It requires that the intended recipient's public key and the sender's RSA
    keypair be provided. It will then generate a symmetric key to encrypt the
    actual message data with. The symmetric key, the sender's public key, a
    signature of the message, and the encrypted message with CBC IV attached
    will be encoded into the picture. It is likewise able to decode and
    decrypt messages embeded in a picture. To do so it requires the
    recipient's RSA keypair.
    """


    def __init__(self, **kwargs):
        """
        Initialize an EncryptedSteganographer object

        Keyword Arguments:
        inputFile -- The filename of the image you wish to embed
            information in.
        outputFile -- The filename of the image that will have your
            information in it.
        message -- A string message.
        messageFile -- The filename of a (text)file you which to embed
            into inputFile and save as outputFile.
        recipientPublicKeyFileName -- The file name of the recipient's public
            key.
        sendersKeyPairFileName -- The file name of the sender's RSA keypair.
        passphrase -- The passphrase for the senders keypair. Unprotected
            keypairs will not be supported.
        """

        try:
            self._recipPubKeyFileName = kwargs.pop("recipientPublicKeyFileName")
        except KeyError:
            print("A public key was not provided so encryption will not" +
                "be possible.")
        try:
            self._senderKeyFileName = kwargs.pop("sendersKeyPairFileName")
            self._passphrase = kwargs.pop("passphrase")
        except KeyError:
            print("A private keypair and a passphrase MUST be provided to" +
                " initialize an EncryptedSteganographer object!")
        super(EncryptedSteganographer, self).__init__(**kwargs)

    def encryptAndEncodeMessage(self):
        """
        This function will encrypt a message and encode it onto an image.
        """

        self._message = CryptoHelper.encryptMessage(self._message,
            self._recipPubKeyFileName, self._senderKeyFileName,
            self._passphrase).dumpMessage()

        self.encodeImage()

    def decryptAndDecodeMessage(self):
        """
        This Method will decode an image with a message in it and then,
        decrypt that message.
        """

        try:
            self.decodeImage()
        except Exception as e:
            print(e)
        self._message = CryptoHelper.decryptMessage(
            Message.loadMessage(self._message), self._senderKeyFileName,
            self._passphrase)

        print( "Message: " + self._message )
        return self._message

if __name__ == "__main__":

    description_string = "This program will embed a message into an image."
    description_string += " It will also encrypt the message when called"
    description_string += " with the appropriate arguments."
    epilog_string = "Thank you for using steganographer!"


    #If we are being executed independantly then parse the necessary arguments.
    parser = argparse.ArgumentParser(description=description_string,
                                    epilog=epilog_string)
    parser.add_argument("--inputimage","-ii",
                        help="The to encode the message onto or the encoded" +
                        " image if decoding.")
    parser.add_argument("--outputimage", "-oi",
                        help="The name of the encoded image.")
    parser.add_argument("--encode", "-e", action="store_true",
                        help="Encode a message onto a picture.")
    parser.add_argument("--decode", "-d", action="store_true",
                        help="Decode the input image and write message to" +
                        " terminal.")
    parser.add_argument("--crypto", action="store_true",
                        help="Use ciphered steganographer instead plaintext")


    parser.add_argument("--message", "-m",
                        help="The message to be encoded onto the picture.")
    parser.add_argument("--inputfile", "-if", help="--inputfile <filename>.")
    parser.add_argument("--outputfile", "-of",
                        help="--outputfile <filename> for decoded text.")


    parser.add_argument("--generate", "-g",
                        help="Generate a key of of size --modulus. If no" +
                        " modulus is provided then 2048 will be used.")
    parser.add_argument("--encryptionkey", "-ec",
                        help="The asymmetric key to use for encrypting.")
    parser.add_argument("--signingkey", "-sk",
                        help="The asymmetric key to use for signing.")
    parser.add_argument("--passphrase", "-p",
                        help="The passphrase to the singing key.")
    parser.add_argument("--modulus", "-m", help="Key modulus size.")


    parser.add_argument("--comparefiles", "-c",
                        help="Read back the first 512 pixels of an image.")
    args = parser.parse_args()

    steg = None
    if args.generate:
        if not args.passphrase:
            print("A passphrase for the key must be provided.")
            exit(1)
        elif args.modulus:
            CryptoHelper.generateKeys(args.generate, args.passphrase,
                                        args.modulus)
        else:
            CryptoHelper.generateKeys(args.generate, args.passphrase)
    elif args.encode:
        if args.crypto:
            pass
    elif args.decode:
        pass
    else:
        args.print_help()
        exit(0)

    #Things went better than expected
    exit(0)