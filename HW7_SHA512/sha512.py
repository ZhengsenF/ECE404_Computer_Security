#!/usr/bin/env python3
# Homework Number: 6
# Name: Zhengsen Fu
# ECN Login: fu216
# Due Date: Mar 12

import sys
from BitVector import *
from enum import Enum


class Register(Enum):
    a = 0
    b = 1
    c = 2
    d = 3
    e = 4
    f = 5
    g = 6
    h = 7


k = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f",
     "e9b5dba58189dbbc", "3956c25bf348b538", "59f111f1b605d019",
     "923f82a4af194f9b", "ab1c5ed5da6d8118", "d807aa98a3030242",
     "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
     "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235",
     "c19bf174cf692694", "e49b69c19ef14ad2", "efbe4786384f25e3",
     "0fc19dc68b8cd5b5", "240ca1cc77ac9c65", "2de92c6f592b0275",
     "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
     "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f",
     "bf597fc7beef0ee4", "c6e00bf33da88fc2", "d5a79147930aa725",
     "06ca6351e003826f", "142929670a0e6e70", "27b70a8546d22ffc",
     "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
     "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6",
     "92722c851482353b", "a2bfe8a14cf10364", "a81a664bbc423001",
     "c24b8b70d0f89791", "c76c51a30654be30", "d192e819d6ef5218",
     "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
     "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99",
     "34b0bcb5e19b48a8", "391c0cb3c5c95a63", "4ed8aa4ae3418acb",
     "5b9cca4f7763e373", "682e6ff3d6b2b8a3", "748f82ee5defb2fc",
     "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
     "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915",
     "c67178f2e372532b", "ca273eceea26619c", "d186b8c721c0c207",
     "eada7dd6cde0eb1e", "f57d4f7fee6ed178", "06f067aa72176fba",
     "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
     "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc",
     "431d67c49c100d4c", "4cc5d4becb3e42b6", "597f299cfc657e2a",
     "5fcb6fab3ad6faec", "6c44198c4a475817"]

k = [BitVector(hexstring=each) for each in k]


def sha512(inputFileName):
    with open(inputFileName) as file:
        input_txt = file.read()
    input_vec = BitVector(textstring=input_txt)
    file_size = input_vec.size

    # padding
    if (1024 - file_size % 1024) < 129:  # still need to ask about size less than 128
        padded = BitVector(intVal=1, size=1)  # padding bit vector concatenated to the end
        space_left = 1024 - file_size % 1024  # spaces that left to pad
        print(space_left)
        padded += BitVector(intVal=0, size=(space_left - 1))
        padded += BitVector(intVal=0, size=(1024 - 128))
        padded += BitVector(intVal=file_size, size=128)
    elif not file_size % 1024:
        padded = BitVector(intVal=1, size=1)  # padding bit vector concatenated to the end
        padded += BitVector(intVal=0, size=(1024 - 1 - 128))
        padded += BitVector(intVal=file_size, size=128)
    else:
        padded = BitVector(intVal=1, size=1)  # padding bit vector concatenated to the end
        space_left = 1024 - file_size % 1024  # spaces that left to pad
        print(file_size % 1024)
        print(space_left)
        print(space_left - 1 - 128)
        padded += BitVector(intVal=0, size=(space_left - 1 - 128))
        padded += BitVector(intVal=file_size, size=128)
    input_vec += padded

    # initial vector and registers
    a = BitVector(hexstring='6a09e667f3bcc908')
    b = BitVector(hexstring='bb67ae8584caa73b')
    c = BitVector(hexstring='3c6ef372fe94f82b')
    d = BitVector(hexstring='a54ff53a5f1d36f1')
    e = BitVector(hexstring='510e527fade682d1')
    f = BitVector(hexstring='9b05688c2b3e6c1f')
    g = BitVector(hexstring='1f83d9abfb41bd6b')
    h = BitVector(hexstring='5be0cd19137e2179')

    word = [None for _ in range(80)]
    # for each block
    for message_lcv in range(0, len(input_vec) // 1024):
        block = input_vec[message_lcv * 1024: message_lcv * 1024 + 1024]

        orig_a = a
        orig_b = b
        orig_c = c
        orig_d = d
        orig_e = e
        orig_f = f
        orig_g = g
        orig_h = h

        # generate 80 message blocks
        for index in range(0, 16):
            word[index] = block[index * 64: index * 64 + 64]
        for index in range(16, 80):
            s0 = sigma_0(word[index - 15])
            s1 = sigma_1(word[index - 2])
            int_word = int(word[index - 16]) + s0 + int(word[index - 7]) + s1
            int_word %= 2 ** 64
            word[index] = BitVector(intVal=int_word, size=64)

        # 80 rounds
        for round_num in range(80):
            registers = [a, b, c, d, e, f, g, h]
            t1 = T1(registers, word[round_num], round_num)
            t2 = T2(registers)
            h = g
            g = f
            f = e
            e = BitVector(intVal=(int(d) + t1) % (2 ** 64), size=64)
            d = c
            c = b
            b = a
            a = BitVector(intVal=(t1 + t2) % (2 ** 64), size=64)
        # after 80 rounds processing
        a = BitVector(intVal=((int(orig_a) + int(a)) % (2 ** 64)), size=64)
        b = BitVector(intVal=((int(orig_b) + int(b)) % (2 ** 64)), size=64)
        c = BitVector(intVal=((int(orig_c) + int(c)) % (2 ** 64)), size=64)
        d = BitVector(intVal=((int(orig_d) + int(d)) % (2 ** 64)), size=64)
        e = BitVector(intVal=((int(orig_e) + int(e)) % (2 ** 64)), size=64)
        f = BitVector(intVal=((int(orig_f) + int(f)) % (2 ** 64)), size=64)
        g = BitVector(intVal=((int(orig_g) + int(g)) % (2 ** 64)), size=64)
        h = BitVector(intVal=((int(orig_h) + int(h)) % (2 ** 64)), size=64)
    return a + b + c + d + e + f + g + h


def T1(registers, w, index):
    # used in round based processing
    # input: list of all registers, word i, index of k
    # return int value of calculated BitVector
    int_result = int(registers[Register.h.value])
    int_result += Ch(registers)
    int_result += sigma_e(registers)
    int_result += int(w)
    int_result += int(k[index])
    return int_result % (2 ** 64)


def T2(registers):
    # used in round based processing
    # input: list of all registers
    # return int value of calculated BitVector
    int_result = sigma_a(registers)
    int_result += Maj(registers)
    return int_result % (2 ** 64)


def Ch(registers):
    # used in round based processing
    # input: list of all registers
    # return int value of calculated BitVector
    e = registers[Register.e.value].deep_copy()
    f = registers[Register.f.value].deep_copy()
    g = registers[Register.g.value].deep_copy()
    return int((e & f) ^ (~e & g))


def Maj(registers):
    # used in round based processing
    # input: list of all registers
    # return int value of calculated BitVector
    a = registers[Register.a.value].deep_copy()
    b = registers[Register.b.value].deep_copy()
    c = registers[Register.c.value].deep_copy()
    return int((a & b) ^ (a & c) ^ (b & c))


def sigma_a(registers):
    # used in round based processing
    # input: list of all registers
    # return int value of calculated BitVector
    a1 = registers[Register.a.value].deep_copy()
    a2 = registers[Register.a.value].deep_copy()
    a3 = registers[Register.a.value].deep_copy()
    return int((a1 >> 28) ^ (a2 >> 34) ^ (a3 >> 39))


def sigma_e(registers):
    # used in round based processing
    # input: list of all registers
    # return int value of calculated BitVector
    e1 = registers[Register.e.value].deep_copy()
    e2 = registers[Register.e.value].deep_copy()
    e3 = registers[Register.e.value].deep_copy()
    return int((e1 >> 14) ^ (e2 >> 18) ^ (e3 >> 41))


def sigma_0(x):
    # used in message block generation
    # input: 64 bit BitVector word
    # return int value of calculated BitVector
    x1 = x.deep_copy()
    x2 = x.deep_copy()
    x3 = x.deep_copy()
    return int((x1 >> 1) ^ (x2 >> 8) ^ (x3.shift_right(7)))


def sigma_1(x):
    # used in message block generation
    # input: 64 bit BitVector word
    # return int value of calculated BitVector
    x1 = x.deep_copy()
    x2 = x.deep_copy()
    x3 = x.deep_copy()
    return int((x1 >> 19) ^ (x2 >> 61) ^ (x3.shift_right(6)))


if __name__ == '__main__':
    result = sha512(sys.argv[1])
    with open(sys.argv[2], 'w') as outFile:
        outFile.write(result.get_hex_string_from_bitvector())

    # debug
    # with open(sys.argv[1], 'r', encoding='utf-8') as file:
    #     input_txt_test = file.read()
    #
    # import hashlib
    # hasher = hashlib.sha512()
    # print(input_txt_test.encode('utf-8'))
    # hasher.update(input_txt_test.encode('utf-8'))
    # print(hasher.hexdigest())
