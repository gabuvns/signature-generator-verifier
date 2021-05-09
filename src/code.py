import sys
import hashlib
import libnum
import base64

e = 65537
p = 3
q = 5
n = p * q
phi = (p-1) * (q-1)
d = libnum.invmod(e, phi)

file_obj = open(r"input.txt", "r")
message = file_obj.readlines()
file_obj.close()

message = ''.join(message)

encoded_bytes = base64.b64encode(message.encode("utf-8"))
# encoded_str = str(encoded_bytes, 'utf-8')
int_b = int.from_bytes(encoded_bytes, 'big')
print()
print(encoded_bytes)
print()
print(int_b)
c = pow(int_b, e, n) 

print()
print(encoded_bytes)
print()
print(c)
print()


dc = pow(c, d, n)

dc = (dc).to_bytes((dc.bit_length() + 7) // 8, byteorder='big')

encoded_str = base64.b64decode(dc)
res = str(encoded_str, 'utf-8')
print(res)