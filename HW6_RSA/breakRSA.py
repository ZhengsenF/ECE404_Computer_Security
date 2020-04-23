#!/usr/bin/env python3
# Homework Number: 6
# Name: Zhengsen Fu
# ECN Login: fu216
# Due Date: Mar 3
from BitVector import *
import sys
from PrimeGenerator import *
import numpy as np

eValue = 3
blockSize = 256


def encryption(messageName, enc1Name, enc2Name, enc3Name, n_1_2_3Name):
    fileNames = [enc1Name, enc2Name, enc3Name]
    with open(n_1_2_3Name, 'w') as fptr:
        for index, each in enumerate(fileNames):
            pVal, qVal = keyGeneration()
            nVal = pVal * qVal
            RSAencryption(messageName, pVal, qVal, each)
            fptr.write(str(nVal))
            if index != 2:
                fptr.write('\n')


def crack(enc1Name, enc2Name, enc3Name, n_1_2_3Name, crackedName):
    with open(n_1_2_3Name) as file:
        nVal = []
        for _ in range(3):
            nVal.append(int(file.readline().strip()))

    fileNames = [enc1Name, enc2Name, enc3Name]
    message = []
    for each in fileNames:
        with open(each) as file:
            fromFile = file.read().strip()
            message.append(BitVector(hexstring=fromFile))
    # N values
    bigN_total = nVal[0] * nVal[1] * nVal[2]
    bigN = []
    bigN_vec = []

    bigN.append(nVal[1] * nVal[2])
    bigN_vec.append(BitVector(intVal=bigN[0]))

    bigN.append(nVal[0] * nVal[2])
    bigN_vec.append(BitVector(intVal=bigN[1]))

    bigN.append(nVal[0] * nVal[1])
    bigN_vec.append(BitVector(intVal=bigN[2]))

    # calculate inverse
    inverse = []
    for index in range(3):
        inverse.append(int(bigN_vec[index].multiplicative_inverse(BitVector(intVal=nVal[index]))))

    outputVec = BitVector(size=0)
    for index in range(0, len(message[0]), blockSize):
        cipher = []
        for lcv in range(3):
            cipher.append(int(message[lcv][index: index + blockSize]))
        m_3 = 0
        for lcv in range(3):
            m_3 += cipher[lcv] * bigN[lcv] * inverse[lcv]
        m_3 = int(m_3) % int(bigN_total)
        decrypted = solve_pRoot(3, m_3)
        outputVec += BitVector(intVal=decrypted, size=128)
    with open(crackedName, 'wb') as file:
        outputVec.write_to_file(file)


def solve_pRoot(p, x):  # O(lgn) solution
    '''
	Finds pth root of an integer x.  Uses Binary Search logic.	Starts
	with a lower bound l and go up until upper bound u.	Breaks the problem into
	halves depending on the search logic.  The search logic says whether the mid
	(which is the mid value of l and u) raised to the power to p is less than x or
	it is greater than x.	Once we reach a mid that when raised to the power p is
	equal to x, we return mid + 1.

	Author: Shayan Akbar
		sakbar at purdue edu

	'''

    # Upper bound u is set to as follows:
    # We start with the 2**0 and keep increasing the power so that u is 2**1, 2**2, ...
    # Until we hit a u such that u**p is > x
    u = 1
    while u ** p <= x: u *= 2

    # Lower bound set to half of upper bound
    l = u // 2

    # Keep the search going until upper u becomes less than lower l
    while l < u:
        mid = (l + u) // 2
        mid_pth = mid ** p
        if l < mid and mid_pth < x:
            l = mid
        elif u > mid and mid_pth > x:
            u = mid
        else:
            # Found perfect pth root.
            return mid
    return mid + 1


def RSAencryption(plainFileName, pValue, qValue, encryptedFileName):
    half_blockSize = int(blockSize / 2)
    nValue = pValue * qValue
    inputVector = BitVector(filename=plainFileName)  # bit vector that contains file
    outputFile = open(encryptedFileName, 'w')
    while inputVector.more_to_read:
        blockVector = inputVector.read_bits_from_file(half_blockSize)  # read 128 bits from file
        if blockVector.size % half_blockSize:
            blockVector.pad_from_right(half_blockSize - (blockVector.size % half_blockSize))
        blockVector.pad_from_left(half_blockSize)
        encryptedValue = pow(int(blockVector), eValue, nValue)
        outputVec = BitVector(intVal=encryptedValue)
        outputVec.pad_from_left(blockSize - outputVec.size)
        outputStr = outputVec.get_bitvector_in_hex()
        outputFile.write(outputStr)
    outputFile.close()


def keyGeneration():
    # this function randomly generate p and q for encryption and decryption
    myGenerator = PrimeGenerator(bits=int(blockSize / 2))
    done = False
    while not done:
        pValue = myGenerator.findPrime()
        qValue = myGenerator.findPrime()
        co_prime = GCD(pValue - 1, eValue) and GCD(qValue - 1,
                                                   eValue)  # condition that p value and q value are co-prime to e
        not_equal = pValue != qValue  # condition that p and q are not equal
        if co_prime and not_equal:
            done = True
    return pValue, qValue


def GCD(a, b):
    while b:
        a, b = b, a % b
    return a


if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == '-e':
        messageName_main = sys.argv[2]
        enc1Name_main = sys.argv[3]
        enc2Name_main = sys.argv[4]
        enc3Name_main = sys.argv[5]
        n_1_2_3Name_main = sys.argv[6]
        encryption(messageName_main, enc1Name_main, enc2Name_main, enc3Name_main, n_1_2_3Name_main)
    elif mode == '-c':
        enc1Name_main = sys.argv[2]
        enc2Name_main = sys.argv[3]
        enc3Name_main = sys.argv[4]
        n_1_2_3Name_main = sys.argv[5]
        crackedName_main = sys.argv[6]

        crack(enc1Name_main, enc2Name_main, enc3Name_main, n_1_2_3Name_main, crackedName_main)
