---
title: "Shodan.io - TryHackMe"
author: krishna
description: "Walkthrough of Shodan.io from TryHackMe"
date: 2020-10-20 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [web, tool]
---

**[Shodan.io](https://tryhackme.com/room/shodan)**

bro, i'm so stupid :cry:, how do i get past this memory. i did a `mv linuxprivesc.md shodan.md` instead of transferring to another directory as `mv linuxprivesc.md shodan.md folder_to_move_to/`. how do i stop regretting this?

i'll try to put in as much efforts as the first write-up

## Task 1 - Introduction

nice - ping, get ip, search [ultratools](https://www.ultratools.com/tools/asnInfo), get ASN number, then go to [shodan](http://www.shodan.io)

## Task 2 - Getting Started

1. What is Google's ASN number?

	![ultratools search](/assets/img/tryhackme/shodan/shodan1.png)

	`AS15169`

2. When was it allocated? Give the year only.

	`2000`

3. Where are most of the machines on this ASN number, physically in the world?

	![shodan search](/assets/img/tryhackme/shodan/shodan2.png)

	`United States`

4. What is Google's top service across all their devices on this ASN?

	`SSH`

5. What SSH product does Google use?

	![ssh product](/assets/img/tryhackme/shodan/shodan3.png)

	`OpenSSH`

6. What is Google's most used Google product, according to this search? Ignore the word "Google" in front of it.

	`Cloud`

## Task 3 - Filters

nifty search features

## Task 4 - Google & Filtering

1. What is the top operating system for MYSQL servers in Google's ASN?

	`5.6.40-84.0-log`

2. What is the 2nd most popular country for MYSQL servers in Google's ASN?

	`Netherlands`

3. Under Google's ASN, which is more popular for nginx, Hypertext Transfer Protocol or Hypertext Transfer Protocol(s)?

	`Hypertext Transfer Protocol`

	![web server](/assets/img/tryhackme/shodan/-shodan5.png)

	![http or https ig](/assets/img/tryhackme/shodan/shodan6.png)

4. Under Google's ASN, what is the most popular city?

	`Mountain View`

5. Under Google's ASN in Los Angeles, what is the top operating system according to Shodan?

	`PAN-OS`

	![hmm pan os ay?](/assets/img/tryhackme/shodan/shodan7.png)

6. Using the top Webcam search from the explore page, does Google's ASN have any webcams? Yay / nay.

	`Nay`

	![nice, no webcams up](/assets/img/tryhackme/shodan/shodan8.png)

## Task 5 - Exploring the API & Conclusion

nice post, really informative. good job.
