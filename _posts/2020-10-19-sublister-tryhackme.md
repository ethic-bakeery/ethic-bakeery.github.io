---
title: "Sublist3r - TryHackMe"
author: krishna
description: "Walkthrough of Sublist3r from TryHackMe"
date: 2020-10-19 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [web, tool]
---

**[Sublist3r from TryHackMe](https://tryhackme.com/room/rpsublist3r)**

## Task 1 - Intro

so cool, a subdomain finder

## Task 2 - Installation

just basic setup

## Task 3 - Switchboard

1. What switch can we use to set our target domain to perform recon on?

	`-d`

2. How about setting which engines we'll use for searching? (i.e. google, bing, etc)

	`-e`

3. Saving our output is important both so we don't have to run recon again but also so we can return to our returns and review them at a later time. What switch do we use to define an output file?

	`-o`

4. Sublist3r can sometimes take some time to run but we can speed through up the use of threads. Which switch allows us to set the number of threads?

	`-t`

5. Last but not least, we can also bruteforce the domains for our target. This isn't always the most useful, however, it can sometimes find a key domain that we might have missed. What switch allows us to enable brute forcing?

	`-b`

## Task 4 - Scans away!

1. Let's run sublist3r now against nbc.com, a fairly large American news company. Run this now with the command: `python3 sublist3r.py -d nbc.com -o sub-output-nbc.txt`

	![sublister results](/assets/img/tryhackme/sublister/sublister1.png)

2. Once that completes open up your results and take a look through them. Email domains are almost always interesting and typically have an email portal (usually Outlook) located at them. Which subdomain is likely the email portal? 

	`mail`

3. Administrative control panels should never be exposed to the internet! Which subdomain is exposed that shouldn't be?

	`admin`

4. Company blogs can sometimes reveal information about internal activities, which subdomain has the company blog at it?

	`blog`

5. Development sites are often vulnerable to information disclosure or full-blown attacks. Two developer sites are exposed, which one is associated directly with web development?

	`dev-www`

6. Customer and employee help desk portals can often reveal internal nomenclature and other potentially sensitive information, which dns record might be a helpdesk portal?

	`help`

7. Single sign-on is a feature commonly used in corporate domains, which dns record is directly associated with this feature? Include both parts of this subdomain separated by a period.

	`ssologin.stg`

8. One last one for fun. NBC produced a popular sitcom about typical office work environment, which dns record might be associated with this show?

	`office-words`
