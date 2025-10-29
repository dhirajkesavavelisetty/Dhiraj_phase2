# 1. RSA oracle
Can you abuse the oracle?
An attacker was able to intercept communications between a bank and a fintech company. They managed to get the message (ciphertext) and the password that was used to encrypt the message.
Additional details will be available after launching your challenge instance.

## Solution:
- as given in the hint i explored cpa attack on rsa and figured out to crack the rsa interpretter i type in a third cipher so that it decrypts it and then we can accordingly derive the decryption of the password
- so i learn about pwn tools before so i used them to create a script first i read the interpretter and encrypt the number 5.
- then i multiply the cipher of 5 and the password provided to create a third cipher and decrypt it to give an output.
- now i take the hex output and convert it to decimal followed by division with 5 since i multiplied it by5 and then convert that value back to hex followed by conversion to ascii to get an output which is the key to move on
- as mentioned in the hint i typed out the openssl command and then key in the secret.enc provided followed by the key we found from the decrypter and hence we obtain the flag

```
from pwn import *
server = remote('titan.picoctf.net', 59318)
response = server.recvuntil('decrypt.')
print(response.decode())

input = b'E' + b'\n'
server.send(input)

response = server.recvuntil('keysize):')
print(response.decode())

input = b'\x05' + b'\n'
server.send(input)
response = server.recvuntil('ciphertext (m ^ e mod n)')
response = server.recvline()
num=int(response.decode())*4228273471152570993857755209040611143227336245190875847649142807501848960847851973658239485570030833999780269457000091948785164374915942471027917017922546

response = server.recvuntil('decrypt.')
print(response.decode())
input = b'D' + b'\n'
server.send(input)

response = server.recvuntil('decrypt:')
print(response.decode())
server.send(str(num)+'\n')

response = server.recvuntil('hex (c ^ d mod n):')
print(response.decode())
response = server.recvline()
print(response.decode())
```

## Flag:
```
picoCTF{su((3ss_(r@ck1ng_r3@_da099d93}
```
## Concepts learnt:
- rsa is a method encoding between two organisations and is used by them to transfer messages using encryptions. I learnt about the public keys as well as private keys that are maintined by the organisations and how they are exchanged
- i learnt a lot about rsa and the methods of cipher and how plain text attack shall be carried out to crack the cipher. The linke below are full of resources and important for any future challenges
## Resources:
- [about rsa](https://www.geeksforgeeks.org/computer-networks/rsa-algorithm-cryptography/)
- [understanding rsa](https://www.youtube.com/watch?v=hm8s6FAc4pg&pp=ygUDcnNh)
- [about cpa on rsa](https://www.youtube.com/watch?v=cC8kKIvve-M)(https://www.youtube.com/watch?v=wwkhSL5QWQc)
- [cpa on rsa](https://www.geeksforgeeks.org/computer-networks/chosen-ciphertext-attacks-on-rsa/)

***


# 2. custom encryption
- read the python encryption file and create a decryption file

## Solution:
- so i started by understanding the cipher python script provided and first few functions which were key exchanges more on that in notes - following this was the xor encryption where the plain text which was entered was reversed and then each character of the text and test was converted to ascii value and bitwise xor operation was used followed by converting it back to character.
- the next function was encrypt function which converted the plaintext to ascii and multiplied it with the value of key and constant number 311 and this cipher was printed.
- so what i did was i started by going to the xor function and created a decrypt function below encrypt function which takes the cipher as input and creates a plain text string and for every number it divides it by key and 311 and convert from ascii value to an integer and return the plain
- so now we go to xor and create a xor decrypt function which takes the semi cipher as input and we creat a plaintext string and perform the xor operation and store the value obtained in the plain text.
- since in the encryption xor was perfomred first followed by encryption in the decryption we reverse the process.
- no we move down to the input place and instead of taking input we remove the input function and directly paste our encrypted numbers provided and hence the system decrypts these numbers and proived the flag

```
from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def encrypt(plaintext, key):
    cipher = []
    for char in plaintext:
        cipher.append(((ord(char) * key*311)))
    return cipher

def decrypt(ciphertext, key):
    plain = ""
    for num in ciphertext:
        plain += chr(int((num/ key /311)))
    return plain

def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key):
    cipher_text = ""
    key_length = len(text_key)
    for i, char in enumerate(plaintext[::-1]):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return 
    
def dynamic_xor_decrypt(ciphertext, text_key):
    plain_text = ""
    key_length = len(text_key)
    for i, char in enumerate(ciphertext):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        plain_text += decrypted_char
    return plain_text


def test(cipher_text, text_key):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print("Enter prime numbers")
        return
    a = 90 #randint(p-10, p) #87-97
    b = 26 #randint(g-10, g) #21-31
    print(f"a = {a}")
    print(f"b = {b}")
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    semi_cipher = decrypt(cipher_text, shared_key)
    plain = dynamic_xor_decrypt(semi_cipher, text_key)
    print(f'plain is: {plain[::-1]}')


if __name__ == "__main__":
    message = [61578, 109472, 437888, 6842, 0, 20526, 129998, 526834, 478940, 287364, 0, 567886, 143682, 34210, 465256, 0, 150524, 588412, 6842, 424204, 164208, 184734, 41052, 41052, 116314, 41052, 177892, 348942, 218944, 335258, 177892, 47894, 82104, 116314]
    test(message, "trudeau")

```
## Flag:
```
picoCTF{custom_d2cr0pt6d_49fbee5b}
```
## Concepts learnt:
- i learnt what keys are how keys between two organisations are created and exchanged for encyption and decryption and called the diffiehellman key exchange in the links below
- sysarv is a form of taking input string by string in python and i did explore different terms that come through in python
- Learnt how wxactly a bitwise xor operator runs where it convers charcaters to their ascii values and then converts them to binary and bitwise does the xor operation and hence converts them back to ascii and accoridngly we can move forward to our approproate needs.

## Notes:
- i did spend a lot of time in trying to write the decrypting code for the given encryption as i am a python beginner and should soon spend some time and learnt deeper python fundamentals to quickly write codes when in need and not serach up small commands that should be known
## Resources:
- [python script writing](https://w3schools.com/python/)
- [understanding ciphers and basics or crytography](https://youtube.com/playlist?list=PLBlnK6fEyqRhBsP45jUdcqBivf25hyVkU)
- [understand the exchange of keys](https://www.geeksforgeeks.org/computer-networks/diffie-hellman-key-exchange-and-perfect-forward-secrecy/)

***


# 3. miniRSA
- use the values provided to get the flag
## Solution:
- so i moved to the web and searched up about rsa and how keys are exchanged between two organisations fro encrypted transfer of data and i learn about a bunch of variables for encrypted and decrypted text
- i opened up a rsa decoder online and typed out the respective variables and then i obtained the flag

## Flag:
```
picoCTF{n33d_a_lArg3r_e_606ce004}
```
## Concepts learnt:
- i learnt what keys are how keys between two organisations are created and exchanged for encyption and decryption and called the diffiehellman key exchange in the links below
- rsa is a method encoding between two organisations and is used by them to transfer messages using encryptions. I learnt about the public keys as well as private keys that are maintined by the organisations and how they are exchanged
## Resources:
- [rsa decoder](https://www.dcode.fr/rsa-cipher)
- [about rsa](https://www.geeksforgeeks.org/computer-networks/rsa-algorithm-cryptography/)
- [understanding rsa](https://www.youtube.com/watch?v=hm8s6FAc4pg&pp=ygUDcnNh)
- [about common ciphers](https://www.youtube.com/playlist?list=PLBlnK6fEyqRhBsP45jUdcqBivf25hyVkU)
***