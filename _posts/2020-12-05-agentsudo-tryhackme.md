---
title: "Agent Sudo - TryHackMe"
author: krishna
description: "Walkthrough of Agent Sudo CTF from TryHackMe"
date: 2020-12-05 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [ctf, privesc, steg, linux, osint]
pin: true
---

**[Agent Sudo from TryHackMe](https://tryhackme.com/room/agentsudoctf)**

## Task 1 - Author note

nice

## Task 2 - Enumerate

starting with a nmap scan, we get

![](/assets/img/tryhackme/agentsudo/agentsudo1.png)
_the good ol' nmap scan_

1. How many open ports?

	`3` - 21, 22 and 80

So, we first try the webserver because anonymous login on ftp is not allowed and we don't know any ssh creds

2. How you redirect yourself to a secret page?

	by changing the `User-Agent` as the homepage says. the hints suggest changing it to `C`.

	so upon intercepting the request in burpsuite and changing the headers like this,

	![](/assets/img/tryhackme/agentsudo/agentsudo2.png)
	_customizing request headers in burpsuite repeater_

	we get,

	![](/assets/img/tryhackme/agentsudo/agentsudo3.png)
	_response headers in burpsuite_

3. What is the agent name?

	`Chris` as evident

## Task 3 - Hash cracking and brute-force

1. FTP password

	on bruteforcing ftp with hydra, we get

	![](/assets/img/tryhackme/agentsudo/agentsudo4.png)
	_bruteforcing with hydra_

	on ftp-ing, we see the following files

	![](/assets/img/tryhackme/agentsudo/agentsudo5.png)
	_files from ftp_

	**To_agentJ.txt**,

	> Dear agent J,
	>
	> All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.
	>
	> From,
	>
	> Agent C

	so, from these instructions, we try `binwalk` to examine the contents of these images

	![](/assets/img/tryhackme/agentsudo/agentsudo6.png)
	_binwalk-ing_

	so, `cutie.png` contains a zip file inside it, but it is password-protected

2. Zip file password

	we could use `zip2john` and `john` to crack it easily

	![](/assets/img/tryhackme/agentsudo/agentsudo14.png)
	_john the ripper_

	to give hint, the zip file's password will be like `a****`

3. steg password

	![](/assets/img/tryhackme/agentsudo/agentsudo7.png)
	_To\_agentR.txt_

	but this is not the passphrase for the stegofile

	so, this must be encrypted, we can use **[CyberChef](https://gchq.github.io/CyberChef/)**'s **magic** recipe to try and decrypt it

	![](/assets/img/tryhackme/agentsudo/agentsudo8.png)
	_cyberchef's magic_

4. Who is the other agent (in full name)?

	we can use `steghide` to extract the hidden message

	```console
	$ steghide --extract -sf cute-alien.jpg
	Enter passphrase: 
	wrote extracted data to "message.txt".
	```

5. SSH password

	![](/assets/img/tryhackme/agentsudo/agentsudo9.png)
	_not so secret anymore_

## Task 4 - Capture the user flag

1. What is the user flag?

	![](/assets/img/tryhackme/agentsudo/agentsudo10.png)
	_user flag_

2. What is the incident of the photo called?

	after `scp`-ing the `Alien_autopsy.jpg` file, and googling about it

	![](/assets/img/tryhackme/agentsudo/agentsudo11.png)
	_x-files' theme plays_

	so, the answer seems to be `Roswell Alien Autopsy`

## Task 5 - Privilege escalation

first thing to do, would be to run `sudo -l` and `sudo -V`

![](/assets/img/tryhackme/agentsudo/agentsudo12.png)
_privesc 101_

1. CVE number for the escalation (Format: CVE-xxxx-xxxx)

	a google search of the superuser privs of J gives us the reqd exploit-db link

	so, the number will be `CVE-2019-14287`

2. What is the root flag?

	![](/assets/img/tryhackme/agentsudo/agentsudo13.png)
	_aha!_

3. (Bonus) Who is Agent R?

	`DesKel`

v cool, thank you creator of Agent Sudo room
