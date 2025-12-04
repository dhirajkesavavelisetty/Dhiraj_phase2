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
```

Day-4
Ai in security
