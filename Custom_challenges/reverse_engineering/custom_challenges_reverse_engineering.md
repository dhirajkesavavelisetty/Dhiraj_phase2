
Custom challenges- Reverse engineering

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
















apktool d veridisQuo.apk -o app_files
byuCTF{e4_if_e_efcopukd0inrccyat}
