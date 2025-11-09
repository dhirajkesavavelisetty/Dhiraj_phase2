Custom challenges - Cryptography


# 1. all signs alien
- decode the given python script and data give to obtain the flag

## Solution:
- the question provided a encrypting code where a random integer was generated and set of mathematical operations are done to check for a specific condiotn (more in the videos below) and another function where the negative is generated.
- a fixed value a is taken and the code outputs one value for each of the bits where one is positive to encode on type of bit and the other is negative to encode the other type of bit.
- 1 is generated if the condiotn is satisfied or -1 but we dont know if it stands for the output as 0 or as 1 so we must try decoding both ways
- for eahc output value v in our script we compute the date and if we get value 1 then it is a quadratic residue and if we get output p-1 then it is a quadratic no residue
- so first option we assume it is a residue and code 0 if i is 1 and code 1 if i is p-1
- second option is we assume it is a non residue and code 1 if i is 1 and code 0 if i is p-1
- we collect the bits in the order and find out that we got 263 bits so we add a zero infornt so it doesnt change the number and then we now convert this 264 bits to text and obtain the flag
- ![binary to text](all_signs_align_binary-text.png)

```
import sys

p = 9129026491768303016811207218323770273047638648509577266210613478726929333106121387323539916009107476349319902011390210650434835260358014251332047605739279

def compute_list(values):
    return [pow(v,(p-1)//2,p) for v in values]

def binary_from_output(computeted_input):
    # consider and print both the posibilities
    binary_A=[]
    binary_B=[]
    for i in computeted_input:
        if i == 1:
            binary_A.append('0')
            binary_B.append('1')
        elif i == p-1:
            binary_A.append('1')
            binary_B.append('0')
    return ''.join(binary_A), ''.join(binary_B)

#MAIN 
path = 'out.txt'
with open(path, 'r') as f:
    s = f.read().strip()
input = eval(s) 

output_computation = compute_list(input)

binary_A=binary_from_output(output_computation)
binary_B=binary_from_output(output_computation)

print("Binary: ")
print(binary_A)
print(binary_B)
```
-![binary to text](all_signs_align_binary-text.png)
## Flag:
```
nite{r3s1du35_f4ll1ng_1nt0_pl4c3}
```
## Concepts learnt:
- i learnt a lot about using the python in general for ctfs as wel as coding
- i learnt in depth about qudratic residue, eulers criteria, representation symbols, primtive roots more of which can be understood in the videos below
- refer to the attached playlist as well
## Resources:
-[quadratic residue](https://www.youtube.com/watch?v=M6gDsFhQugM)
-[eulers criterion](https://www.youtube.com/watch?v=2IBPOI43jek)

***


# 3. Quixorte
- find the decyrption in the python file and obtain the flag
## Solution:
- so understanding the script first the rotate function performs right bit shift and left bit shift and or operator is run between them followed by and operator with another number bit by bit. Then there is a xor function where xor is applied after rotation and every time it is appended it is xored with the already xored array and then appended with a key which is genretaed randomly but of 8 bytes as mentioned.
- so first to obtain the key we know the magic btes or the first few bytes of a png file which are the standard header files so we obtain those standard bytes and then first apply the rotate function. Now we apply the multiple xor function by intialising a xor prefix array to 0 and then we apply xor function twice along with the xor prefix every time to obtain the key and eventually we get the key
- now with this key as reference we take the encoded data and de rotate and followed by the and operator. Now with the key we dexor the the encoded data and finally save this data and export the decoded png file .When i opened the png file i got the flag.
```
def rotate(b, i):
    i %= 8
    return ((b >> i) | ((b << (8 - i)) & 0xFF)) & 0xFF
def derotate(b, i):
    i %= 8
    return (((b << i) & 0xFF) | (b >> (8 - i))) & 0xFF

def decrypt(encoded, final):
    with open(encoded, "rb") as f:
        enc = bytearray(f.read())

    n = len(encoded)
    key = 8 
    magic_bytes = bytearray([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

    rot_magic = [rotate(b, i) for i, b in enumerate(magic_bytes)]
    key = [0] * key

    xor_out = 0
    for k in range(key):
        key[k] = rot_magic[k] ^ encoded[k] ^ xor_out
        xor_out ^= key[k]

    key_bytes = bytes(key)
    print("key:", key_bytes.hex())

    decoded = bytearray(encoded)
    for i in reversed(range(n-key+1)):
        for j in range(key):
            decoded[i + j] ^= key_bytes[j]

    flag = bytearray(derotate(b, i) for i, b in enumerate(decoded))

    with open(final, "wb") as f:
        f.write(flag)
    print("decrypted", final)


decrypt("quote.png.enc", "quote_decrypted.png")

```
## Flag:
```
nite{t0_b3_XOR_n0t_t0_b3333}
```
## Concepts learnt:
- i learnt a lot about xoring and its properties and in the dexor function we start backward since we have to undo all the xors and hence obtain the dexor function. This attention was very important in writing the dexor function

## Resources:
-[magic bytes](https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5)
-[properties of xor](https://medium.com/@Harshit_Raj_14/useful-properties-of-xor-in-coding-bitwise-manipulation-and-bitmasking-2c332256bd61)
***
