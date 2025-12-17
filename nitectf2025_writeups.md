    Nite_CTF 2025
Writeups


# 1. Quick mistake  -->  Forensics
- analyse the pcap file and obtain the flag
## Solution:
- (1) analyzed the PCAP and found a GET /telemetry request to localhost that returned an encrypted JSON file labeled telemetry_sslkeylog. Now we decrypted the keys using the seed, salt, and info found in the handshake packet and ran a Python script to derive the key which gave us the ssl/tls secrets. These saved these secrets to a keys.log file and load it into wireshark's TLS preferences. This decrypted the hidden HTTP traffic.
- (2) By filtering for http, i saw the attacker interacting with the internal server and identified as 192.0.2.66 from the source IP column. I found the connection ID by inspecting the QUIC header of the flag response packet (Packet 377) and found the destination connection ID: 2457ce19cb87e0eb.
- (3) The attacker requested /source (Packet 373) so i extracted the response data, which turned out to be a compressed TAR archive containing the server's code and the attacker requested /flag (Packet 377) so i extracted the response token. Then i ran a script that decompressed the source code archive, found the Fernet Key hidden inside the .env file, and used it to decrypt the flag.
Result: qu1c_d4t4gr4m_pwn3d

## Flag:
```
nite{192.0.2.66_2457ce19cb87e0eb_qu1c_d4t4gr4m_pwn3d}
```
## Resources:
- i did refere to forensics challeneg from picoctf which we solved using wireshark analysing a pcap file
***


# 2. Antakshari  -->  AI
- Two NumPy arrays were given:
`handout/latent_vectors.npy` 
`handout/partial_edges.npy` 
- The server asks us to Enter the Actor Node Sequence in Descending Order and submitting a correct 6-node sequence of actors returns the flag 
## Solution:
- first we inspect the given files and the embedings might be a two movies and split nodes into two where high might be movies and low might be actors.
- we can build similarity matrix for each movie and rank actor nodes by dot product.
- The web endpoint expects exactly six actor IDs in descending order so we automated trying every movie node: take its top-6 most similar actors, sort them descending, submit, and stop when the response is not “Incorrect”
```
import numpy as np
lv=np.load('handout/latent_vectors.npy')
edges=np.load('handout/partial_edges.npy')
print(lv.shape, edges.shape)
print(edges)
```
- script:
```

import numpy as np, requests, json

from sklearn.cluster import KMeans



lv = np.load('handout/latent_vectors.npy')

norms = np.linalg.norm(lv, axis=1)

labels = KMeans(n_clusters=2, random_state=0).fit(norms.reshape(-1, 1)).labels_

movie_label = 1 if norms[labels==1].mean() > norms[labels==0].mean() else 0

movies = np.where(labels == movie_label)[0]

actors = np.where(labels != movie_label)[0]

M = lv @ lv.T



url = '<https://antakshari1.chall.nitectf25.live/api/verify>'

headers = {'Content-Type': 'application/json'}



for movie in movies:
    sims = M[movie, actors]

    order = np.argsort(-sims)

    top6 = actors[order[:6]]

    seq = ','.join(str(x) for x in sorted(top6, reverse=True))

    r = requests.post(url, headers=headers, data=json.dumps({'node_sequence': seq}), timeout=10)

    res = r.json().get('result', '')

    print(f"movie {movie} -> {seq} -> {res}")

    if 'Incorrect' not in res:
        break
```
- success appears at movie node 3
movie 3 -> 189,177,134,108,37,29
## Flag:
```
nite{Diehard_1891771341083729}
```
## Resources:
- [understanding numpy arrays](https://www.w3schools.com/python/numpy/default.asp)
***


# 3. Floating point guardian  -->  AI
- the server asks for a 15 floating point and computes the probability and if that equals a target it prints the flag
- server: ncat --ssl floating.chals.nitectf25.live 1337
## Solution:
- first we gothorugh the src.c wher we input 15 double values where:
  - i%4 == 0: `xor_activate(x, key)` — converts `x` to a fixed-point integer `long_val = (long)(x * 1_000_000)`, XORs with `key` (per-input constant), then converts back to double by dividing by `1e6`.
  - i%4 == 1: `tanh(x)`
  - i%4 == 2: `cos(x)`
  - i%4 == 3: `sinh(x / 10.0)`
  - All hidden activations use `tanh`.
  - Output uses a linear combiner + `sigmoid`.
  - Target probability is `TARGET_PROBABILITY = 0.7331337420` and `EPSILON = 1e-5`. The program checks `fabs(probability - TARGET_PROBABILITY) < EPSILON`
  - the indices with xor_activate are quantized to micro-units (1e-6) and then XORed with fixed integer keys — those inputs are effectively discretized and can only change output when the integer representation int(x * 1e6) changes.

- now we implement this in python
z = logit(TARGET) = ln(TARGET / (1 - TARGET)) ≈ 1.0105805171
- Start from a reasonable initial guess where many activations are near neutral:
- For `cos` inputs (i%4 == 2) use `x = π/2` so `cos(x) ≈ 0`.
- For `xor` inputs (i%4 == 0) start with `x = key / 1e6` so `xor_activate(x, key)` 
- For others use small values (0).
-  Use a randomized local search / hillclimbing procedure that:
- Adjusts continuous inputs by small gaussian noise.
- Adjusts `xor` inputs by integer increments to account for the XOR behavior.
- Keeps best candidate and reduces step-size over time.

```
import math
import random

TARGET = 0.7331337420
EPS = 1e-7
random.seed(1)

XOR_KEYS = [0x42, 0x13, 0x37, 0x99, 0x21, 0x88, 0x45, 0x67,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE]

# weight and bias tables copied exactly from src.c

W1 = [

[0.523, -0.891, 0.234, 0.667, -0.445, 0.789, -0.123, 0.456],
[-0.334, 0.778, -0.556, 0.223, 0.889, -0.667, 0.445, -0.221],
[0.667, -0.234, 0.891, -0.445, 0.123, 0.556, -0.789, 0.334],
[-0.778, 0.445, -0.223, 0.889, -0.556, 0.234, 0.667, -0.891],
[0.123, -0.667, 0.889, -0.334, 0.556, -0.778, 0.445, 0.223],
[-0.891, 0.556, -0.445, 0.778, -0.223, 0.334, -0.667, 0.889],
[0.445, -0.123, 0.667, -0.889, 0.334, -0.556, 0.778, -0.234],
[-0.556, 0.889, -0.334, 0.445, -0.778, 0.667, -0.223, 0.123],
[0.778, -0.445, 0.556, -0.667, 0.223, -0.889, 0.334, -0.445],
[-0.223, 0.667, -0.778, 0.334, -0.445, 0.556, -0.889, 0.778],
[0.889, -0.334, 0.445, -0.556, 0.667, -0.223, 0.123, -0.667],
[-0.445, 0.223, -0.889, 0.778, -0.334, 0.445, -0.556, 0.889],
[0.334, -0.778, 0.223, -0.445, 0.889, -0.667, 0.556, -0.123],
[-0.667, 0.889, -0.445, 0.223, -0.556, 0.778, -0.334, 0.667],
[0.556, -0.223, 0.778, -0.889, 0.445, -0.334, 0.889, -0.556]
]

B1 = [0.1, -0.2, 0.3, -0.15, 0.25, -0.35, 0.18, -0.28]

W2 = [
[0.712, -0.534, 0.823, -0.445, 0.667, -0.389],
[-0.623, 0.889, -0.456, 0.734, -0.567, 0.445],
[0.534, -0.712, 0.389, -0.823, 0.456, -0.667],
[-0.889, 0.456, -0.734, 0.567, -0.623, 0.823],
[0.445, -0.667, 0.823, -0.389, 0.712, -0.534],
[-0.734, 0.623, -0.567, 0.889, -0.456, 0.389],
[0.667, -0.389, 0.534, -0.712, 0.623, -0.823],
[-0.456, 0.823, -0.667, 0.445, -0.889, 0.734]
]

B2 = [0.05, -0.12, 0.18, -0.08, 0.22, -0.16]

W3 = [[0.923], [-0.812], [0.745], [-0.634], [0.856], [-0.723]]

B3 = [0.42]

# Activations:

def xor_activate(x, key):
long_val = int(x * 1_000_000)
long_val ^= key
return long_val / 1_000_000.0

def forward(inputs):
    # hidden layer 1
    h1 = [0.0] * 8
    for j in range(8):
        for i in range(15):
            mod = i % 4 
                if mod == 0:
                    a = xor_activate(inputs[i], XOR_KEYS[i])
                elif mod == 1:
                    a = math.tanh(inputs[i])
                elif mod == 2:
                    a = math.cos(inputs[i])
                else:
                    a = math.sinh(inputs[i] / 10.0)

h1[j] += a * W1[i][j]
h1[j] += B1[j]
h1[j] = math.tanh(h1[j])

# hidden layer 2

h2 = [0.0] * 6
for j in range(6):
     for i in range(8):
         h2[j] += h1[i] * W2[i][j]
         h2[j] += B2[j]
         h2[j] = math.tanh(h2[j])
         out = sum(h2[i] * W3[i][0] for i in range(6)) + B3[0]
        prob = 1.0 / (1.0 + math.exp(-out))
        return prob

# Randomized search/hillclimb

def search(iterations=120000):

    # initial guess: set cos inputs to pi/2 (cos≈0), xor inputs near key/1e6

    inp = [0.0] * 15

    for idx in [0, 4, 8, 12]:
        inp[idx] = XOR_KEYS[idx] / 1_000_000.0
         for idx in [2, 6, 10, 14]:
             inp[idx] = math.pi / 2
        best = inp[:]
         best_prob = forward(best)
         best_err = abs(best_prob - TARGET)
         scale = 1.0

    for step in range(iterations):

                cand = best[:]

                 idx = random.randrange(15)

                 if idx % 4 == 0:

                         # discrete step in micro-units

                         delta = random.randint(-30, 30)

                     cand[idx] = max(0.0, cand[idx] + delta / 1_000_000.0)

                else:

                         cand[idx] += random.gauss(0, scale)
                  prob = forward(cand)

                err = abs(prob - TARGET)

                 if err < best_err:

                        best_err = err

                         best = cand

                            best_prob = prob

                 if step % 20000 == 0 and step > 0:

                         scale *= 0.7

            return best, best_prob, best_err



if __name__ == '__main__':

         best, prob, err = search()

        print('best prob:', prob)

    print('err:', err)

    print('\\nInputs (Q1..Q15):')

    for v in best:
     print(repr(v))
```
```
HOST=floating.chals.nitectf25.live

PORT=1337

# The exact inputs we found (one per line):
cat <<EOF | ncat --ssl $HOST $PORT
0.000107
-3.158916950799659
1.5707963267948966
0.2950895004463653
0.00006
0.010848294004179542
1.7320580997363282
0.07781283712174002
0
0
1.5707963267948966
1.40376119519013
0.000169
0
1.5707963267948966
```
- compiling and running src.c and obserevd probability to be 0.7331338299 and sending that input to the server
## Flag:
```
nite{br0_i5_n0t_g0nn4_b3_t4K1n6_any1s_j0bs_34x}
```
***


# 4. Stronk Rabin  -->  Cryptography
- the server exposes the encoding and decoding and we shall recover flag inside the cipher text
## Solution:
- For any m, ENC(m) = m^2 mod N - m^2 - ENC(m) = kN. GCD over a few random m reveals N.
- DEC(1) returns sum of 7-8 CRT-combined roots. Different calls pick different shuffles - outputs vary. For composite M, gcd(DEC(1)_i - DEC(1)_j, M) leaks a non-trivial factor with good probability; recurse to split fully.
- Once primes known, enumerate 2^4 CRT roots of C; pick candidate containing prefix nite
- Recover N: send several ENC queries on large random m; gcd of m^2-ENC(m) gives N.
Factor N: repeat DEC(1) twice, gcd of differences with current composite; recursively split until primes.
Decrypt: compute all 16 CRT roots of C; check for nite in roots or their negatives; output flag.
```
import json
import random
from math import gcd
from typing import List
from Crypto.Util.number import long_to_bytes
from pwn import remote
from sympy import isprime
from sympy.ntheory.modular import crt

HOST = "stronk.chals.nitectf25.live"
PORT = 1337

def recv_json(io):
    while True:
        line = io.recvline(timeout=5)
         if not line:
             raise EOFError("connection closed")
         line = line.decode().strip()
    try:
        return json.loads(line)
        except json.JSONDecodeError:
       continue

def enc(io, m: int) -> int:
    io.sendline(json.dumps({"func": "ENC", "args": [int(m)]}).encode())
    return int(recv_json(io)["retn"])

def dec(io, c: int) -> int:
    io.sendline(json.dumps({"func": "DEC", "args": [int(c)]}).encode())
    return int(recv_json(io)["retn"])



def recover_modulus(io, rounds: int = 8) -> int:
    g = 0
     for _ in range(rounds):
         m = random.getrandbits(1200)
         c = enc(io, m)
        d = abs(m * m - c)
         g = d if g == 0 else gcd(g, d)

    for _ in range(3):
        m = random.getrandbits(400)
         if enc(io, m) != pow(m, 2, g):
        raise ValueError("modulus recovery failed")
         return g



def get_factor(io, n: int) -> int:

    while True:
        a = dec(io, 1)
        b = dec(io, 1)
        g = gcd(abs(a - b), n)
        if 1 < g < n:
            return g

def factorize(io, n: int) -> List[int]:
    factors = [n]
    res = []
    while factors:
         f = factors.pop()
        if isprime(f):
             res.append(f)
             continue
         g = get_factor(io, f)
         factors.extend([g, f // g])
     return res

def recover_flag(C: int, primes: List[int]) -> bytes:
    roots = [[pow(C, (p + 1) // 4, p), (-pow(C, (p + 1) // 4, p)) % p] for p in primes]
    N = 1
    for p in primes:
         N *= p
    candidates = []
     for mask in range(16):
         residues = [roots[i][(mask >> i) & 1] for i in range(4)]

         val = int(crt(primes, residues)[0])
        candidates.append(val % N)

    for x in candidates:
         b = long_to_bytes(x)
         if b.startswith(b"nite{") or b.find(b"nite{") != -1:
            return b
        b_neg = long_to_bytes((N - x) % N)
        if b_neg.startswith(b"nite{") or b_neg.find(b"nite{") != -1:
             return b_neg

    chosen = max(candidates)
     if chosen <= N // 2:
         chosen = N - chosen
        return long_to_bytes(chosen)

def main():
    io = remote(HOST, PORT, ssl=True)
    banner = recv_json(io)
    C = int(banner["C"]) if "C" in banner else int(recv_json(io)["C"])
    print(f"[*] C = {C}")
    N = recover_modulus(io)
    print(f"[*] N bits = {N.bit_length()}")
    primes = factorize(io, N)
    primes.sort()

    print(f"[*] factors: {[hex(p) for p in primes]}")
    flag = recover_flag(C, primes)
    print(f"[*] flag: {flag.decode(errors='ignore')}")

    io.close()

if __name__ == "__main__":

     main()
```
## Flag:
```
nite{rabin_stronk?_no_r4bin_brok3n}
```
***

# 5. Ophelia Truth Part 1  --> Forensics
- A detective at Moscow PD, Department 19, receives a message asking him to check the forensic analysis portal for a DNA report. Attached to the message is a file containing a link to the portal. He opens the attachment, but initially, nothing seems to happen, so he overlooks it. Later, he realizes that a crucial file from an ongoing case has gone missing. He has provided the forensic artifacts from his computer to you, his colleague at the cyber forensics department, to figure out what went wrong.
- Windows memory dump file (8GB .raw file)
## Solution:
- first we have to see what we are working with so it is a windows 10 system and windows dump was captured after the incident occured and since the detective recieved two files we use grep and find files with names like dna, report etc.
```
vol3 -f ophelia.raw windows.filescan | grep -iE "dna|forensic|report|portal" | head -20
```
- we found a url `dna_analysis_portal.url` and when we open it opens some malicious working directory enabling hijacking.
- now once we explore we see that runtimebroker.exe was spawned by explorer.exe after .url was opened for malicious activity.
- like advent of cyber we open userassist registry analysis and we find the ip and as well as ports.
- this attack is a recently discovered vulnerability in windows file handling which allows an attacker to bypass windows security warnings, malicious code, infilitarte files as well. (CVE-2025-33053)
## Flag:
```
nite{dna_analysis_portal.url_10.72.5.205_CVE-2025-33053}
```
***


# 6. Hash Vegas  --> Cryptography

## Solution:
- roulette.py draws random.randrange(0, 2**256-1) each round and prints the exact number when you guess, leaking eight tempered 32-bit MT19937 outputs per round.
- slotmachine.py draws two 32-bit choices per spin and displays all 16 nybbles as symbols
- chall.py allows at most 64 roulette rounds and 56 slot spins before the machines break. That yields 64*8 + 56*2 = 624 tempered outputs: exactly one full MT19937 state window.
- lottery.py shuffles an array of 2048 hash functions (1024 sha256, 1023 sha3_224, 1 sha1) once, then for each ticket draws ticket_id = randint(1, 11) and hash_idx = randint(0, len(hash_funcs)-1). A voucher is issued only when ticket_id > 5.
- Voucher generation: ticket_hash = hash_func((secret + ticket_data).encode()).digest()[:20], with ticket_data = username|amount. The secret is 16 random bytes, hex-encoded (32 chars). Redemption tries sha256, sha3_224, then sha1 against the same secret-prefix message and pays the parsed amount on match.
- so the solution is we play roulette 64 times, always guessing 0/red. Each round, read the printed number and split it into eight 32-bit words; collect 512 words and then spin the slot machine 56 times, parse the 16 symbols back to two 32-bit words per spin; collect the remaining 112 words. Total: 624 outputs.
- then we recreate hash_funcs, shuffle it with the recovered PRNG, and simulate lottery draws until ticket_id > 5 and the chosen hash function is SHA-1. Count how many tickets to skip then burn that many lottery attempts with pay=0.
- we then Buy the predicted winning ticket (pay 1). Capture voucher_data and voucher_code
- Perform SHA-1 length extension with known original length = 32 (secret hex) + len(voucher_data). Append `|1000000000`, obtain forged digest and data and obtain the forged voucher to set balance to $1,000,000,000.
```
```
## Flag:
```
import re
import ssl
import struct
import socket
import hashlib
import random
import time
from typing import List, Tuple

HOST = "vegas.chals.nitectf25.live"
PORT = 1337
USERNAME = "a"
TARGET_AMOUNT = 1_000_000_000

MASK_32 = 0xFFFFFFFF
SYMBOLS = [
    "\\U0001F352", "\\U0001F34B", "\\U0001F34A", "\\U0001F347",
    "\\U0001F349", "\\U0001F353", "\\U0001F34D", "\\U0001F34E",
    "\\U0001F34F", "\\U0001F350", "\\U0001F351", "\\U0001F348",
    "\\U0001F34C", "\\U0001F96D", "\\U0001F95D", "\\U0001F965",
]

SYMBOL_TO_VAL = {s: i for i, s in enumerate(SYMBOLS)}

def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        try:
            chunk = sock.recv(4096)
        except TimeoutError as exc:
            raise TimeoutError(f"timeout waiting for {marker!r}, got: {data!r}") from exc
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data

def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\\n").encode())

def split_words(num: int, words: int = 8) -> List[int]:
    return [(num >> (32 * i)) & MASK_32 for i in range(words)]

def undo_right_xor(y: int, shift: int) -> int:
    x = 0
    for i in range(32):
        idx = 31 - i
        bit = (y >> idx) & 1
        if idx + shift < 32:
            bit ^= (x >> (idx + shift)) & 1
        x |= bit << idx
    return x & MASK_32

def undo_left_xor_mask(y: int, shift: int, mask: int) -> int:
    x = 0
    for idx in range(32):
        bit = (y >> idx) & 1
        if idx - shift >= 0 and (mask & (1 << idx)):
            bit ^= (x >> (idx - shift)) & 1
        x |= bit << idx
    return x & MASK_32

def untemper(y: int) -> int:
    y = undo_right_xor(y, 18)
    y = undo_left_xor_mask(y, 15, 0xEFC60000)
    y = undo_left_xor_mask(y, 7, 0x9D2C5680)
    y = undo_right_xor(y, 11)
    return y & MASK_32

def parse_roulette_num(blob: str) -> int:
    m = re.search(r"number is\\s+(\\d+)", blob)
    if not m:
        raise ValueError(f"could not parse roulette number from: {blob}")
    return int(m.group(1))

def parse_wheels(blob: str) -> Tuple[int, int]:
    wheels: List[str] = []
    for line in blob.splitlines():
        if any(sym in line for sym in SYMBOLS):
            tokens = [tok for tok in line.split() if tok in SYMBOL_TO_VAL]
            if tokens:
                wheels.extend(tokens)
    if len(wheels) != 16:
        raise ValueError("failed to parse wheels")
    vals = [SYMBOL_TO_VAL[t] for t in wheels]
    out1 = sum(vals[i] << (4 * i) for i in range(8))
    out2 = sum(vals[i + 8] << (4 * i) for i in range(8))
    return out1, out2

def rebuild_state(outputs: List[int]) -> random.Random:
    if len(outputs) != 624:
        raise ValueError("need exactly 624 outputs")
    state = [untemper(x) for x in outputs]
    r = random.Random()
    r.setstate((3, tuple(state + [624]), None))
    return r

def sha1_padding(message_len: int) -> bytes:
    padding = b"\\x80"
    while (message_len + len(padding)) % 64 != 56:
        padding += b"\\x00"
    padding += struct.pack(">Q", message_len * 8)
    return padding

def sha1_length_extend(orig_digest: bytes, orig_len: int, append_data: bytes):
    if len(orig_digest) != 20:
        raise ValueError("orig_digest must be 20 bytes")
    h = list(struct.unpack(">5I", orig_digest))
    total_len_before = orig_len + len(sha1_padding(orig_len))
    new_message = append_data + sha1_padding(total_len_before + len(append_data))

    def sha1_compress(data: bytes, hvals):
        h0, h1, h2, h3, h4 = hvals
        for chunk_start in range(0, len(data), 64):
            chunk = data[chunk_start : chunk_start + 64]
            w = list(struct.unpack(">16I", chunk))
            for i in range(16, 80):
                val = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
                w.append(((val << 1) | (val >> 31)) & MASK_32)
            a, b, c, d, e = h0, h1, h2, h3, h4
            for i in range(80):
                if i < 20:
                    f = (b & c) | (~b & d)
                    k = 0x5A827999
                elif i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                temp = ((a << 5) | (a >> 27)) + f + e + k + w[i]
                temp &= MASK_32
                e, d, c, b, a = d, c, (b << 30 | b >> 2) & MASK_32, a, temp
            h0 = (h0 + a) & MASK_32
            h1 = (h1 + b) & MASK_32
            h2 = (h2 + c) & MASK_32
            h3 = (h3 + d) & MASK_32
            h4 = (h4 + e) & MASK_32
        return [h0, h1, h2, h3, h4]

    new_state = sha1_compress(new_message, h)
    new_digest = struct.pack(">5I", *new_state)
    forged_data = sha1_padding(orig_len) + append_data
    return new_digest, forged_data

def main():
    ctx = ssl.create_default_context()
    for attempt in range(3):
        try:
            with ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST) as s:
                s.settimeout(30)
                s.connect((HOST, PORT))
                banner = recv_until(s, b"Enter your username:")
                print("received banner bytes", len(banner))
                send_line(s, USERNAME)
                time.sleep(0.2)
                menu_intro = recv_until(s, b"Enter your choice:")
                print("received menu bytes", len(menu_intro))

                outputs: List[int] = []
                has_menu = True
                for i in range(64):
                    if i % 10 == 0:
                        print(f"roulette {i}/64")
                    if not has_menu:
                        recv_until(s, b"Enter your choice:")
                    send_line(s, "2")
                    recv_until(s, b"Enter your guess:")
                    send_line(s, "0")
                    recv_until(s, b"Enter color")
                    send_line(s, "R")
                    chunk = recv_until(s, b"Enter your choice:")
                    num = parse_roulette_num(chunk.decode(errors="ignore"))
                    outputs.extend(split_words(num, 8))
                    has_menu = True

                for i in range(56):
                    if i % 10 == 0:
                        print(f"slot {i}/56")
                    if not has_menu:
                        recv_until(s, b"Enter your choice:")
                    send_line(s, "1")
                    chunk = recv_until(s, b"Enter your choice:")
                    out1, out2 = parse_wheels(chunk.decode(errors="ignore"))
                    outputs.append(out1)
                    outputs.append(out2)
                    has_menu = True

                assert len(outputs) == 624
                predictor = rebuild_state(outputs)

                funcs = [hashlib.sha256] * 1024 + [hashlib.sha3_224] * 1023 + [hashlib.sha1]
                predictor.shuffle(funcs)

                skips = 0
                while True:
                    ticket_id = predictor.randint(1, 11)
                    hash_idx = predictor.randint(0, len(funcs) - 1)
                    func = funcs[hash_idx]
                    if ticket_id > 5 and func == hashlib.sha1:
                        break
                    skips += 1
                print("skips", skips)

                for _ in range(skips):
                    if not has_menu:
                        recv_until(s, b"Enter your choice:")
                    send_line(s, "3")
                    recv_until(s, b"How much are you going to pay")
                    send_line(s, "0")
                    recv_until(s, b"Enter your choice:")
                    has_menu = True

                if not has_menu:
                    recv_until(s, b"Enter your choice:")
                send_line(s, "3")
                recv_until(s, b"How much are you going to pay")
                send_line(s, "1")
                chunk = recv_until(s, b"Enter your choice:")
                has_menu = True
                text = chunk.decode(errors="ignore")
                m_data = re.search(r"Voucher data:\\s*([0-9a-fA-F]+)", text)
                m_code = re.search(r"Voucher code:\\s*([0-9a-fA-F]+)", text)
                if not (m_data and m_code):
                    raise RuntimeError("failed to capture voucher")
                voucher_data_hex = m_data.group(1)
                voucher_code_hex = m_code.group(1)

                orig_data = bytes.fromhex(voucher_data_hex)
                orig_digest = bytes.fromhex(voucher_code_hex)
                orig_len = 32 + len(orig_data)

                append = f"|{TARGET_AMOUNT}".encode()
                new_digest, forged_suffix = sha1_length_extend(orig_digest, orig_len, append)
                forged_data_hex = (orig_data + forged_suffix).hex()
                forged_code_hex = new_digest.hex()

                if not has_menu:
                    recv_until(s, b"Enter your choice:")
                send_line(s, "4")
                recv_until(s, b"Enter voucher code")
                send_line(s, forged_code_hex)
                recv_until(s, b"Enter voucher data")
                send_line(s, forged_data_hex)
                recv_until(s, b"Enter your choice:")
                has_menu = True

                send_line(s, "6")
                flag_chunk = recv_until(s, b"Enter your choice:")
                print(flag_chunk.decode(errors="ignore"))
                return
        except Exception as exc:
            print(f"attempt {attempt+1} failed: {exc}")
            time.sleep(2)
    raise SystemExit("all attempts failed")

if __name__ == "__main__":
    main()
```
***