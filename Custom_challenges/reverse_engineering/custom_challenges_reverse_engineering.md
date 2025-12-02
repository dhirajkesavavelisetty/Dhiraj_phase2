
Custom challenges- Reverse engineering


# 1. Joy division
- crack the provided .elf file to obtain the flag

## Solution:
- so first the file palantinpackflag.txt is being manipulated and is saved in a file flag.txt.
- reading through using ghidra we understand that flipbites manipulates bytes and function expand expands the size of conte. so first we reduce size of content and unflip the bits.
- for even indexes it does bitwise NOT operation and for even index it does bitwise XOR operation starting 0x69 and adding 0x20 every time it occurs
- First it allocates a new buffer which is twice the size of input and then it splits the bytes into two parts. It then combines the parts using & operator with a key in combination which is generated every time it is expanded. The dynamic key starts with 0x69, and then multiplied by 0x20 and then the combination used bvar1, so we swap order of the high and low halfs
- the python script reverses the function by first reducing size of bits followed by flipping them.

```
def reverse_flipBits(data):
    result = bytearray()
    key = 0x69
    var = False

    for b in data:
        if not var:
            result.append(~b & 0xFF)
        else:
            result.append(b ^ key)
            key = (key + 0x20) & 0xFF

        var = not var

    return bytes(result)


def reverse_expand_once(data):
    result = bytearray()
    key = 0x69
    var = False

    for i in range(0, len(data), 2):
        a = data[i]
        b = data[i+1]

        key_hi = (key >> 4) & 0xF
        key_lo = key & 0xF

        if not var:
            lo = a & 0x0F
            hi = b & 0xF0
            original = hi | lo
        else:
            hi = a & 0xF0
            lo = b & 0x0F
            original = hi | lo

        result.append(original)

        key = (key * 0x0B) & 0xFF
        var = not var

    return bytes(result)


def reverse_expand_n_times(data, n):
    for _ in range(n):
        data = reverse_expand_once(data)
    return data

with open("flag (1).txt", "rb") as f:
    expanded = f.read()

step1 = reverse_expand_n_times(expanded, 3)
original = reverse_flipBits(step1)
print(original.decode)
```

## Flag:
```
sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}
```
## Concepts learnt:
- i learnt more about python functions and how to write scripts to obtain flags
- i learn about how to reverse files using ghidra and yunderstand the functions using registers and various other aspects of functions embedded in the assembly language
***


# 2. Worthy.knight
- crack the provided .elf file

## Solution:
- i put the file in hxd and figured out it is a .elf file type so i started reverse engineering by uploading it to ghidra for the output
- first there are various varibles initialised followed by initializing the string variable and then it takes an input after the prompt. The first condition is that it checks if there are 10 characters. Now the catch is the program checks pairwise so first it checks if both characters are alphabetical or else it rejects the input. 
- next it checks if both the characters are uppercase or lowercase so they must be of opposite case and since loop increments by 2 it runs 5 times.
- pair one is when character 1 and chracter 2 is xored to obtain a specific value so by that we find the first two characters of the flag
- pair two checks the next two characters which do they same thing so hence we obtain those characters as well
- in the third pair first the bytes are reversed so 6,5 are being coded using md5 which takes in two bytes and hashes them to a 16 byte output, converts it to lowercase hex characters. It loops over 16 bytes each into two hex characters. Since we need two byte combinations and the ascii of letter range from 65-122 we can create a python script to brute force and get the two letters of the md5 hash.
- the fourth pair and fifth pair are again the same as the first two where two are xored to obtain a specific output so we obtain those letters as well

```
import hashlib

for a in range(122):
    for b in range(122):
        if hashlib.md5(bytes([a, b])).hexdigest() == "33a3192ba92b5a4803c9a9ed70ea5a9c":
            print(a, b, chr(a), chr(b))

```
## Flag:
```
KCTF{NjkSfTYaIi}
```
## Concepts learnt:
- MD5 is a hash function:
it takes a sequence of bytes and produces a fixed 16-byte output. every different 2-byte input gives a completely different 16-byte output. 
## Resources:
-[md5 hash](https://www.avast.com/c-md5-hashing-algorithm)
***


# 3. Time
- crack the provided .elf file

## Solution:
- This is a conventional number guessing game basically and upto us to find out the right number to obtain the flag. The code calls the function time which basically returns current calendar time of the system. This time is measured as the number of seconds passed since 00:00:00
- i researhed about how to compile and run these type of files using gdb and installed it on the system. 
- first we run the time.elf file and then we use break which pauses the code wherever there is an srand rand function so that we can inspect the time anf use it for the answer. Then we run the program and enter that specific number we obtained when we paused the file. The value basically exits in the memroy so we followe that and we use ito and obtain the flag

```
gdb ./time.elf
Reading symbols from ./time...
(No debugging symbols found in ./time)

(gdb) break rand
Breakpoint 1 at 0x400790

(gdb) run
Starting program: /mnt/c/Users/user/downloads/time
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, rand () at ./stdlib/rand.c:26
26      ./stdlib/rand.c: No such file or directory.

(gdb) finish
Run till exit from #0  rand () at ./stdlib/rand.c:26
0x000000000040095f in main ()
Value returned is $1 = 473914306

Value returned is $1 = 473914306
(gdb) continue
Continuing.
Welcome to the number guessing game!
I'm thinking of a number. Can you guess it?
Guess right and you get a flag!
Enter your number: 473914306
Your guess was 473914306.
Looking for 473914306.
You won. Guess was right! Here's your flag:
Flag file not found!  Contact an H3 admin for assistance.
```
## Flag:
```
You won. Guess was right! Here's your flag:
Flag file not found!  Contact an H3 admin for assistance.
```
## Concepts learnt:
- GDB = GNU Debugger. It’s a tool that lets us run a program under controlled conditions, pause it, inspect, change execution state, step through instructions, set breakpoints, and call functions and more.
- Programs can have bugs or behaviour that only appears at runtime. A debugger lets a developer observe the program while it’s running — you can see the live values of variables and the flow of execution.

## Resources:
- [abour gdb](https://www.geeksforgeeks.org/c/gdb-step-by-step-introduction/)


# 4. VeridisQuo
- crack the apk file to obtain the flag

## Solution:
- i used a command line tool called apktool d it unpacked everything and gives us images and things like how the app runs and the .dex files. Apktool makes these .dex files readable by converting them into smali, which is Android’s version of assembly. Then we use a tool called JADX to convert the .dex files directly into Java source code.
- once we open it in jadex we see so many files out of which one files was byuctf and might contain the next steps and it contained a file called main activity

- ```setContentView(R.layout.activity_main);
  Utilities util = new Utilities;
  util.cleanUp();```
	
    this Sets the user interface layout for this activity. It links the Java code to the XML layout file named activity_main.xml, which defines the visual elements of the screen. Then it creates a new instance of the Utilities class, passing this the Utilities class likely contains helper functions and then the cleanUp() method on the Utilities object.(this prompt has been obtain from AI since i had to understand the java code)

- so then i opened utilities.java and it contains many flag parts from 1 to 28 indicating the flag is split into numbered pieces and since in the main function layout was set to activity_main we shall open activity_main.xml file and read it so i search for it and it is present in Res/layout/activity_main.xml and hence we find the characters but are arranged in an order by VALUES OF HOW FAR THEY APPEAR FROM THE BOTTTOM so greated the number higher it appears on the screen.
- so i look through the numbers given for each character given on the screen  using the margin bottom and layout width and accordingly order the charcters as well as using some common sense to obtain a meaningful flag.

## Flag:
```
byuctf{android_piece_0f_c4ke}
```
## Concepts learnt:
- i learnt how to use the tool called apktool which essecntially breaks and provides all the files in an apk file.
- i learnt what and how apk files are generally made where androidManifest.xml is typically the identity card and other things like lib and res contain resoucres and libraries used by the application.
- i learnt about jadex which simplies the output of apktool as well as a software called android studio which is an IDE for building apps and os for the android platform

## Resources:
- [reverse engineering apk](https://medium.com/@prathunan777/reverse-engineering-android-apps-ctf-challenge-baa3a9cbe7d5)
- [about apk](https://www.studytonight.com/android/android-app-package-structure)
***


# 5. Dusty
- open the three rust files to obtain the flag

## Solution:
- at first i put the file in ghidra and the main function has line ```_ZN3std2rt10lang_start17h91ff47afc442db24E``` which is the naming method used for the function ```_ZN10shinyclean4main17h4b15dd54e331d693E``` and this is for the main function shinyclean so we go to that function
- in thet function the abstack_c7 is initialized with byte constants and now these bytes are indivdiually xored with 0x3f and produces another byte array
- now this byte array is compared with PID a process id assigned and checks if it is equal to a specific value then it prints the new bbyte array so basically the new byte array is the flag
- now i took the initiliazed charcaters individually and xored them with 0x3f to obtain the flag
```
7b ^ 3f = 44 - D
5e ^ 3f = 61 - a
48 ^ 3f = 77 - w
58 ^ 3f = 67 - g
7c ^ 3f = 43 - C
6b ^ 3f = 54 - T
79 ^ 3f = 46 - F
44 ^ 3f = 7b - {
79 ^ 3f = 46 - F
6d ^ 3f = 52 - R
0c ^ 3f = 33 - 3
0c ^ 3f = 33 - 3
60 ^ 3f = 5f - _
7c ^ 3f = 43 - C
0b ^ 3f = 34 - 4
6d ^ 3f = 52 - R
60 ^ 3f = 5f - _
68 ^ 3f = 57 - W
0b ^ 3f = 34 - 4
0a ^ 3f = 35 - 5
77 ^ 3f = 48 - H
1e ^ 3f = 21 - !
42 ^ 3f = 7d - }
```

## Flag:
```
DawgCTF{FR33_C4R_W45H!}
```
## Concepts learnt:
- i learnt about rust as a whole and how they are reverse engineered thought this challenge didnt need that much
## Notes:

## Resources:

***

