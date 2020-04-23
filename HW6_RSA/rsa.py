#!/usr/bin/env python3
# Homework Number: 6
# Name: Zhengsen Fu
# ECN Login: fu216
# Due Date: Mar 3

from BitVector import *
import sys
from PrimeGenerator import *

blockSize = 256
eValue = 65537


def keyGeneration(pFileName, qFileName):
    # this function randomly generate p and q for encryption and decryption
    myGenerator = PrimeGenerator(bits=int(blockSize / 2))
    done = False
    while not done:
        pValue = myGenerator.findPrime()
        qValue = myGenerator.findPrime()
        co_prime = GCD(pValue - 1, eValue) and GCD(qValue - 1, eValue)  # condition that p value and q value are co-prime to e
        not_equal = pValue != qValue  # condition that p and q are not equal
        if co_prime and not_equal:
            done = True
    with open(pFileName, 'w') as file:
        file.write(str(pValue))
    with open(qFileName, 'w') as file:
        file.write(str(qValue))


def GCD(a, b):
    while b:
        a, b = b, a % b
    return a


def encryption(plainFileName, pFileName, qFileName, encryptedFileName):
    half_blockSize = int(blockSize / 2)
    # read p value and q value from the file
    with open(pFileName) as file:
        pValue = int(file.read().strip())
    with open(qFileName) as file:
        qValue = int(file.read().strip())
    nValue = pValue * qValue
    # eVector = BitVector(intVal=eValue)
    # nVector = BitVector(intVal=nValue)
    # dVector = eVector.multiplicative_inverse(nVector)
    inputVector = BitVector(filename=plainFileName)  # bit vector that contains file
    outputFile = open(encryptedFileName, 'w')
    while inputVector.more_to_read:
        blockVector = inputVector.read_bits_from_file(half_blockSize)  # read 128 bits from file
        # pad the block if necessary
        if blockVector.size % half_blockSize:
            blockVector.pad_from_right(half_blockSize - (blockVector.size % half_blockSize))
        blockVector.pad_from_left(half_blockSize)
        # encryption exponent modulus
        encryptedValue = pow(int(blockVector), eValue, nValue)
        # output the block to file
        outputVec = BitVector(intVal=encryptedValue)
        outputVec.pad_from_left(blockSize - outputVec.size)
        outputStr = outputVec.get_bitvector_in_hex()
        outputFile.write(outputStr)
    outputFile.close()


def decryption(encryptedFileName, pFileName, qFileName, decryptedFileName):
    half_blockSize = int(blockSize / 2)
    # read p value and q value from the file
    with open(pFileName) as file:
        pValue = int(file.read().strip())
    with open(qFileName) as file:
        qValue = int(file.read().strip())
    with open(encryptedFileName) as file:
        hexStr = file.read().strip()
    # calculate values necessary to CTR
    nValue = pValue * qValue
    eVector = BitVector(intVal=eValue)
    nVector = BitVector(intVal=nValue)
    pVec = BitVector(intVal=pValue)
    qVec = BitVector(intVal=qValue)
    n_to = BitVector(intVal=((pValue - 1) * (qValue - 1)))
    dVector = eVector.multiplicative_inverse(n_to)
    dValue = int(dVector)
    xp = qValue * qVec.multiplicative_inverse(pVec).int_val()
    xq = pValue * pVec.multiplicative_inverse(qVec).int_val()
    vValue = dValue % (pValue - 1)
    uValue = dValue % (qValue - 1)
    outputVec = BitVector(size=0)

    for index in range(0, len(hexStr) // 64):
        blockVec = BitVector(hexstring=hexStr[index*64: (index + 1)*64])
        cipher = int(blockVec)
        # use CTR
        vp = pow(cipher, vValue, pValue)  # for chinese reminder theorem
        vq = pow(cipher, uValue, qValue)  # for chinese reminder theorem
        decrypted = (vp * xp + vq * xq) % nValue
        decryptedVec = BitVector(intVal=decrypted, size=128)
        outputVec += decryptedVec

    with open(decryptedFileName, 'wb') as file:
        outputVec.write_to_file(file)


if __name__ == '__main__':
    mode = sys.argv[1]

    if mode == '-g':  # generate
        pFileNameInput = sys.argv[2]
        qFileNameInput = sys.argv[3]
        keyGeneration(pFileNameInput, qFileNameInput)
    elif mode == '-e' or '-d':  # decryption or encryption
        inputFileNameInput = sys.argv[2]
        pFileNameInput = sys.argv[3]
        qFileNameInput = sys.argv[4]
        outputFileNameInput = sys.argv[5]
        if mode == '-e':
            encryption(inputFileNameInput, pFileNameInput, qFileNameInput, outputFileNameInput)
        elif mode == '-d':
            decryption(inputFileNameInput, pFileNameInput, qFileNameInput, outputFileNameInput)
    else:
        print('Error choosing mode')

