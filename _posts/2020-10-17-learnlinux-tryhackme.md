---
title: "Learn Linux - TryHackMe"
author: krishna
description: "Walkthrough of Learn Linux from TryHackMe"
date: 2020-10-17 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [linux, privesc]
---

**[Learn Linux from TryHackMe](https://tryhackme.com/room/zthlinux)**

## Task 43 - Bonus Challenge - The True Ending

Find the root flag at `/root/root.txt`

the most interesting challenge of this whole room

just to check, i enumerated all the user-owned files using `find`, and for the user `shiba2` there was this file named `test1234` and other users couldn't access it

![sus file](/assets/img/tryhackme/linux/linux1.png)

on switching user and seeing the contents of the file, it seemed like it had the credentials of another user

this user `nootnoot` had superuser privs, so the flag was accessible now

![yea root flag](/assets/img/tryhackme/linux/linux2.png)
