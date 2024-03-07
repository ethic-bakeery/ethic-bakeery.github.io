---
title: "Simple CTF - TryHackMe"
author: krishna
description: "Walkthrough of Simple CTF from TryHackMe"
date: 2020-10-22 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [web, linux, privesc]
---

**[Simple CTF from TryHackMe](https://tryhackme.com/room/easyctf)**

running our usual nmap scan, we get

![nmap scan](/assets/img/tryhackme/simplectf/simplectf1.png)

* we see that ftp is running at port 21 with anonymous ftp enabled

* a web server is running at port 80 with default homepage

* ssh service is up and running at port 2222

then i ran `gobuster` on the machine to get this

![gobuster scan](/assets/img/tryhackme/simplectf/simplectf2.png)

the 3rd question involved CVEs, so i ran `nmap -A $MACHINE_IP -oX simplectf_nmap.xml` and then ran it through `searchsploit`

![searchsploitXnmap](/assets/img/tryhackme/simplectf/simplectf3.png)

but i didn't get any match for openssh exploit CVEs and other servies were not very conclusive, so i returned to the `gobuster` output and web-based vulns

the `/simple` directory was interesting

![cms made v simple for me](/assets/img/tryhackme/simplectf/simplectf4.png)

so, **cms made simple** is there and we also get a lot of results in `searchsploit`

![cms made simple X searchsploit](/assets/img/tryhackme/simplectf/simplectf5.png)

the version of cms being used was **2.2.8**, so i searched for an exploit that was just after it and i found, `CMS Made Simple < 2.2.10 - SQL Injection`

it was **`CVE-2019-9053`** and that was also the right answer. this was a sql injection based exploit and so the answer to the 4th question was `sqli`

the exploit can be found in `/usr/share/exploitdb/exploits/php/webapps/46635.py`. code was written in python2 and so i created a virtual environment and installed required modules

i had trouble getting the right salt :-( tried for about 2 hrs :-(. so i got the credentials from other writeups

so then i ran `ssh mitch@$MACHINE_IP` and entered the password (not gonna reveal it here, yea don't remark the irony)

![sshed in and user flag](/assets/img/tryhackme/simplectf/simplectf6.png)

as visible, the other user present is `sunbath`

then i ran `sudo -l` to see which programs i'm (ok mitch) is allowed to run as root

```terminal
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

ok it's ezpz now, just launch `vim` with `sudo` and spawn a shell with `:sh`

now we have root shell, so we `cat` the `root` flag with `cat /root/root.txt`

![ez privesc and root flag](/assets/img/tryhackme/simplectf/simplectf7.png)
