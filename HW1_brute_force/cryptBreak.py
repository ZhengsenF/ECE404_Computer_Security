# Homework Number: 1
# Name: Zhengsen Fu
# ECN Login: fu216
# Due Date: Jan 23 2020

# Reference: Lecture note 1 by professor Kak

# Arguments:
# ciphertextFile: String containing file name of the ciphertext (e.g. encrypted.txt )
# key_bv: 16-bit BitVector of the key used to try to decrypt the ciphertext. #Function Description:
# Attempts to decrypt ciphertext contained in ciphertextFile using key_bv and returns
# the original plaintext as a string
from BitVector import *


def cryptBreak(ciphertextFile, key_bv):
    PassPhrase = "Hopes and dreams of a million years"

    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist=[0] * BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i * numbytes:(i + 1) * numbytes]
        bv_iv ^= BitVector(textstring=textstr)

    # Create a bitvector from the ciphertext hex string:
    FILEIN = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring=FILEIN.read())

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector(size=0)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    # Extract plaintext from the decrypted bitvector:
    outputtext = msg_decrypted_bv.get_text_from_bitvector()
    return outputtext


if __name__ == '__main__':
    ciphertextFile_main = 'encrypted.txt'
    # someRandomInteger = 9999  # Arbitrary integer for creating a BitVector
    for someRandomInteger in range(2 ** 16):
        key_bv_main = BitVector(intVal=someRandomInteger, size=16)
        decryptedMessage = cryptBreak(ciphertextFile_main, key_bv_main)
        if 'Mark Twain' in decryptedMessage:
            print('Encryption Broken!')
            print(someRandomInteger)
            print(decryptedMessage)
            break
        else:
            print('Not decrypted yet')
            print(someRandomInteger)

# key is 25202
# message: It is my belief that nearly any invented quotation, played with confidence, stands a good chance to deceive.
