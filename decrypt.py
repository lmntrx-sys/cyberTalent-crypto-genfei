from os import path
import struct

def F(w):
    # Ensures the result stays within 32-bit unsigned integer bounds
    return ((w * 31337) ^ (w * 1337 >> 16)) % 2**32

def decrypt(block):
    # Initial unpack - a, b, c, d represent the final (encrypted) state
    a, b, c, d = struct.unpack("<4I", block)

    # Reverse the 32 rounds (from last to first)
    for rno in range(32):
        # Step 1: Undo the SECOND half-round to get (a_tmp1, b_tmp1, c_tmp1, d_tmp1)
        # Current (a, b, c, d) are the output of the second half-round (a_out, b_out, c_out, d_out)

        # d_out = d_tmp1 ^ 1337  => d_tmp1 = d_out ^ 1337
        d_mid = d ^ 1337

        # c_out = a_tmp1 ^ F(d_mid | F(d_mid) ^ d_mid)  => a_tmp1 = c_out ^ F(d_mid | F(d_mid) ^ d_mid)
        a_mid = c ^ F(d_mid | F(d_mid) ^ d_mid)

        # b_out = b_mid ^ F(d_mid ^ F(a_mid) ^ (d_mid | a_mid)) => b_mid = b_out ^ F(d_mid ^ F(a_mid) ^ (d_mid | a_mid))
        b_mid = b ^ F(d_mid ^ F(a_mid) ^ (d_mid | a_mid))

        # a_out = c_mid ^ F(d_mid | F(b_mid ^ F(a_mid)) ^ F(d_mid | b_mid) ^ a_mid) => c_mid = a_out ^ F(d_mid | F(b_mid ^ F(a_mid)) ^ F(d_mid | b_mid) ^ a_mid)
        c_mid = a ^ F(d_mid | F(b_mid ^ F(a_mid)) ^ F(d_mid | b_mid) ^ a_mid)

        # Update a, b, c, d to the (a_mid, b_mid, c_mid, d_mid) state
        a, b, c, d = a_mid, b_mid, c_mid, d_mid

        # Step 2: Undo the FIRST half-round to get (a_prev, b_prev, c_prev, d_prev)
        # Current (a, b, c, d) are the output of the first half-round (a_mid, b_mid, c_mid, d_mid)

        # d_mid = a_prev ^ 31337  => a_prev = d_mid ^ 31337
        a_prev = d ^ 31337

        # c_mid = d_prev ^ F(a_prev | F(a_prev) ^ a_prev) => d_prev = c_mid ^ F(a_prev | F(a_prev) ^ a_prev)
        d_prev = c ^ F(a_prev | F(a_prev) ^ a_prev)

        # b_mid = c_prev ^ F(a_prev ^ F(d_prev) ^ (a_prev | d_prev)) => c_prev = b_mid ^ F(a_prev ^ F(d_prev) ^ (a_prev | d_prev))
        c_prev = b ^ F(a_prev ^ F(d_prev) ^ (a_prev | d_prev))

        # a_mid = b_prev ^ F(a_prev | F(c_prev ^ F(d_prev)) ^ F(a_prev | c_prev) ^ d_prev) => b_prev = a_mid ^ F(a_prev | F(c_prev ^ F(d_prev)) ^ F(a_prev | c_prev) ^ d_prev)
        b_prev = a ^ F(a_prev | F(c_prev ^ F(d_prev)) ^ F(a_prev | c_prev) ^ d_prev)

        # Update a, b, c, d to the (a_prev, b_prev, c_prev, d_prev) state
        a, b, c, d = a_prev, b_prev, c_prev, d_prev

    return struct.pack("<4I", a, b, c, d)

with open("flag.enc", "rb") as f:
  ct = f.read()

pt_blocks = []
for i in range(0, len(ct), 16):
    block = ct[i:i+16]
    # Pad the last block if it's less than 16 bytes (optional, depending on encryption padding scheme)
    if len(block) < 16:
        block += b'\x00' * (16 - len(block))
    pt_blocks.append(decrypt(block))

# Joining the decrypted blocks into a single bytes object
pt = b"".join(pt_blocks)
print(pt)
