---
title: "Introductory Researching - TryHackMe"
author: krishna
description: "Walkthrough of Introductory Researching from TryHackMe"
date: 2020-10-17 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [osint]
---

**[Introductory Researching from TryHackMe](https://tryhackme.com/room/introtoresearch)**

## Task 1 - Introduction

outines what to expect

## Task 2 - Example Research Question

some questions irked me because of the exact pattern the right answer must be, but i guess it's all fine and well in the end

1. In the Burp Suite Program that ships with Kali Linux, what mode would you use to manually send a request (often repeating a captured request numerous times)?

	ez, it's `repeater` as the description suggests

2. What hash format are modern Windows login passwords stored in?

	yea, no more direct answers

	this [blog](https://medium.com/@anunayb007/introduction-to-hashing-and-how-to-retrieve-windows-10-password-hashes-9c8637decaef) explains it nicely

3. What are automated tasks called in Linux?

	bare googling gets you through this one, why are you even looking here?

4. What number base could you use as a shorthand for base 2 (binary)?

	this was a bit tricky, it is `16` because the hint says it's not `8` and you know, logical reasons

5. If a password hash starts with $6$, what format is it (Unix variant)?

	`SHA512Crypt`. [this](https://www.open.com.au/radiator/ref/User-Password.html) article explains the common ones

## Task 3 - Vulnerability Searching

`searchsploit`, `curl` and `grep` are all you need for this section

**note :** in `searchsploit`, the `-w` parameter gives you the exploit-db link

1. What is the CVE for the 2020 Cross-Site Scripting (XSS) vulnerability found in WPForms?

	```terminal
	$ searchsploit wpforms -w
	$ curl $EXPLOITDB_LINK | grep CVE
	```

	or if you're a fan of one liners, `curl $(searchsploit wpforms -w | grep exploit | cut -f 7 -d ' ') | grep CVE`

2. There was a Local Privilege Escalation vulnerability found in the Debian version of Apache Tomcat, back in 2016. What's the CVE for this vulnerability?

	`searchsploit apache tomcat debian -w` and so on

	*you know the rules, and so do i*

3. What is the very first CVE found in the VLC media player?

	running `searchsploit vlc media player`, gives us a lot of results, so either search on [exploit-db.com](https://www.exploit-db.com) and sort by date or by inspection, the earliest version of vlc media player might contain the first exploit, so go with `VideoLAN VLC Media Player 0.8.6 (PPC) - 'udp://' Format String (PoC)`

4. If I wanted to exploit a 2020 buffer overflow in the sudo program, which CVE would I use?

	`searchsploit sudo buffer -w`

## Task 4 - Manual Pages

just `man` and `grep` the keywords, *man*

## Task 5 - Final Thoughts

overall, nice intro room
