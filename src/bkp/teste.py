import sys

a = 1024

print(a.bit_length())
print((a.bit_length() + 7) // 8)

chunks = [str(a)[i:i+128] for i in range(0, (a.bit_length() + 7) // 8, 128)]
# dc = (dc).to_bytes((dc.bit_length() + 7) // 8, byteorder='big')

a = int.to_bytes(a, 128, 'big')
print(len(a))
print(len(chunks[0]))