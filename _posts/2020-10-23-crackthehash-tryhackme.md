---
title: "Crack the Hash - TryHackMe"
author: krishna
description: "Walkthrough of Crack the Hash from TryHackMe"
date: 2020-10-23 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [crypto]
---

**[Crack the Hash from TryHackMe](https://tryhackme.com/room/crackthehash)**

store the hash of each question in a text file using `echo -n '<hash>' > <hash_file>` (use quotes because some hashes contain **$** which messes up the data going to the file)

almost all of the challenges can be completed by using

* `hashid -m -j <hash_file>`

* `rockyou.txt` wordlist

* `hashcat -m <mode> <hash_file> <location_of_rockyou.txt>`

* `john --wordlist=<location_of_rockyou.txt> --format=<jtr_format> <hash_file>`

* onlline cracking site, [crackstation](https://cracktstation.net)

* this write-up (sometimes, the hashes take too long to crack, so if you don't have enough patience, this is where you should look)

if you don't get proper results with one hashing format, move onto the next (`hashid` isn't always accurate)

## Task 1 - Level 1

1. 48bb6e862e54f2a795ffc4e541caed4d

	`easy` - **MD5**

2. CBFDAC6008F9CAB4083784CBD1874F76618D2A97

	`password123` - **SHA1**

3. 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032

	`letmein` - **SHA256**

4. $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom

	`bleh` - **bcrypt** (jeez this takes a lot of time, yea no it was designed that way)

5. 279412f945939ba78ce0758d3fd83daa

	`Eternity22` - **MD4** (crackstation ftw)

## Task 2 - Level 2

1. *Hash:* F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85

	`paule` - **SHA256** (again)

2. *Hash:* 1DFECA0C002AE40B8619ECF94819CC1B

	`n63umy8lkf4i` - **NTLM** (yea had to try a lot of other formats before this one)

3. *Hash:* $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.

	*Salt:* aReallyHardSalt

	*Rounds:* 5

	`waka99` - **SHA512**

4. *Hash:* e5d8870e5bdd26602cab8dbe07a942c8669e56d6

	*Salt:* tryhackme

	`481616481616` - **HMAC-SHA1** (many SHA1s before this)
