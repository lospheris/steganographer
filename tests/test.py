#!/usr/bin/python
import sys
import os
sys.path.append('..')
from steganographer import *
from Crypto.Hash import SHA256
from message import CryptoHelper

# These are the values that should be expected based on explicit test cases.
pt_message = "The quick brown fox jumped over the lazy dog."
output_file_name = "text_message_output.txt"
output_image_file_name = "message_output_picture.png"
expected_hash = "6bb6c84384cffedb4529ccc23c635e7134a6bff6c0222e8806c28683cdb3559c"
key_file = "test_key.pem"
pubkey_file = "test_key_publiconly.pem"
encrypted_image_file_name = "encrypted_" + output_image_file_name
encrypted_output_file_name = "encrypted_" + output_file_name

steg = Steganographer(inputFile="test_input_picture.jpg",
                      outputFile=output_image_file_name)

steg.encode_message(pt_message)
decoded_message = steg.decode_message()

if decoded_message != pt_message:
    print("Something went wrong either encoding or decoding the message.")
    print("Should have returned: " + pt_message)
    print("Did return: " + decoded_message)
    exit(1)
else:
    print("Unencrypted string message test successful!")
    
steg.encode_message_from_file("test_message.txt")
steg.decode_message_to_file(output_file_name)

my_hash = SHA256.new()
try:
    my_hash.update(open(output_file_name, 'r').read())
except IOError as e:
    print("Couldn't open the outputted text file. Permissions?")
    exit(1)
    
computed_hash = my_hash.hexdigest()

if computed_hash != expected_hash:
    print("The output file from the decoded image didn't not match the hash.")
    print("Expected: " + expected_hash)
    print("Computed: " + computed_hash)
    exit(1)
else:
    print("The outputed file matches the stored hash! Direct file functions work!")

print("Attempting to generate a 4096 bit key.")
try:
    CryptoHelper.generate_keys(key_file, expected_hash, 4096)
except Exception as e:
    print("There was a problem generating the key.")
    print("The following error was encountered: ")
    print(e)
print("The keys were generated successfully!")
steg = EncryptedSteganographer(inputFile="test_input_picture.jpg",
                               outputFile=encrypted_image_file_name,
                               recipientPublicKeyFileName=pubkey_file,
                               sendersKeyPairFileName=key_file,
                               passphrase=expected_hash)
print("Encode message.")
steg.encrypt_and_encode_message(pt_message)

decoded_message = steg.decrypt_and_decode_message()
if decoded_message != pt_message:
    print("Something went wrong either encoding or decoding the message.")
    print("Should have returned: " + pt_message )
    print("Did return: " + decoded_message )
    exit(1)
else:
    print("Encrypted string message test successful!")
    
print("Encode message from file.")
steg.encrypt_and_encode_message_from_file("test_message.txt")

steg.decrypt_and_decode_message_to_file(encrypted_output_file_name)

my_hash = SHA256.new()
try:
    my_hash.update(open(encrypted_output_file_name, 'r').read())
except IOError as e:
    print("Couldn't open the outputted text file. Permissions?")
    exit(1)
    
computed_hash = my_hash.hexdigest()

if computed_hash != expected_hash:
    print("The output file from the decoded image didn't not match the hash.")
    print("Expected: " + expected_hash)
    print("Computed: " + computed_hash)
    exit(1)
else:
    print("The outputted file matches the stored hash! Encrypted direct file functions work!")

print("The library is functioning properly!")

print("Cleaning up!")
os.remove(output_file_name)
os.remove(key_file)
os.remove(pubkey_file)
os.remove(encrypted_output_file_name)
os.remove(encrypted_image_file_name)
os.remove(output_image_file_name)
print("Clean up complete, exiting.")
exit(0)
