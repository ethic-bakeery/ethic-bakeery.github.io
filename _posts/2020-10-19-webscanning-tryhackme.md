---
title: "Web Scanning - TryHackMe"
author: krishna
description: "Walkthrough of Web Scanning from TryHackMe"
date: 2020-10-19 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [web, tool]
---

**[Web Scanning from TryHackMe](https://tryhackme.com/room/rpwebscanning)**

## Task 1 - Pull the lever, Kronk!

ah, a The Emperor's reference

## Task 2 - ...I'm supposed to scan with that?

should i keep mentioning about how you should be running `<tool> --help` and `grep` for the specifics? no? ok

1. First and foremost, what switch do we use to set the target host?

	`-h`

2. Websites don't always properly redirect to their secure transport port and can sometimes have different issues depending on the manner in which they are scanned. How do we disable secure transport?

	`-nossl`

3. How about the opposite, how do we force secure transport?

	`-ssl`

4. What if we want to set a specific port to scan?

	`-p`

5. As the web is constantly evolving, so is Nikto. A database of vulnerabilities represents a core component to this web scanner, how do we verify that this database is working and free from error?

	`-dbcheck`

6. If instructed to, Nitko will attempt to guess and test both files within directories as well as usernames. Which switch and numerical value do we use to set Nikto to enumerate usernames in Apache? Keep in mind, this option is deprecated in favor of plugins, however, it's still a great option to be aware of for situational usage.

	`-mutate 3`

7. Suppose we know the username and password for a web forum, how do we set Nikto to do a credentialed check? Suppose the username is admin and the password is PrettyAwesomePassword1234

	`-id admin:PrettyAwesomePassword1234`

8. Let's scan our target machine, what web server do we discover and what version is it?

	![nikto scan](/assets/img/tryhackme/webscan/webscan1.png)

	`Apache/2.4.7`

9. This box is vulnerable to very poor directory control due to it's web server version, what directory is indexed that really shouldn't be?

	`config`

10. Nikto scans can take a while to fully complete, which switch do we set in order to limit the scan to end at a certain time?

	`-until`

11. But wait, there's more! How do we list all of the plugins are available?

	`-list-plugins`

12. On the flip-side of the database, plugins represent another core component to Nikto. Which switch do we use to instruct Nikto to use plugin checks to find out of date software on the target host? Keep in mind that when testing this command we need to specify the host we intend to run this against. For submitting your answer, use only the base command with the out of date option.

	`-Plugin outdated`

13. Finally, what if we'd like to use our plugins to run a series of standard tests against the target host?

	`-Plugin tests`

## Task 3 - Zip ZAP!

1. Let's start simple and launch zap. This can be done in a number of ways (Commands: owasp-zap, zaproxy) or through launching it in the Kali gui.

	after running `zaproxy`, we're greeted with this. so after entering the *MACHINE_IP* in the URL, we click on **attack**

	![zaproxy](/assets/img/tryhackme/webscan/webscan2.png)

2. Launch ZAP, what option to we set in order to specify what we are attacking?

	`url to attack`

3. Launch the attack against our target! Throughout the course of this attack you may notice this is very similar to Nikto. Similar to Nessus vs. OpenVAS, Nikto and ZAP and both offer different perspectives on a host and, as such, it's useful to know how to leverage both scanning tools in order to maximize your own visibility in a situation wherein 'noise' doesn't particularly matter.

	![spider results](/assets/img/tryhackme/webscan/webscan3.png)

4. ZAP will discover a file that typically contains pages which well-behaved web indexing engines will read in order to know which sections of a site to avoid. What is the name of this file? (Lucky for us, our scanner isn't what we would call 'well-behaved'!)

	`robots.txt`

5. One entry is included in the disallow section of this file, what is it?

	`/`

6. ZAP will find a directory that contains images for our application, what is the path for that directory? (This is what will follows the name/ip of the website)

	`/dvwa/images/`

7. This website doesn't force a secure connection by default and ZAP isn't pleased with it. Which related cookie is ZAP upset about?

	![alerts](/assets/img/tryhackme/webscan/webscan4.png)

	`httponly`

8. Featured in various rooms on TryHackMe, Cross-Site Scripting is a vicious attack that is becoming ever more common on the open web. What Alert does ZAP produce to let us know that this site is vulnerable to XSS? Note, there are often a couple warnings produced for this, look for one more so directly related to the web client.

	`Web Browser XSS Protection is not enabled`

9. The ZAP proxy spider represents the component responsible for 'crawling' the site. What site is found to be out of scope?

	`http://www.dvwa.co.uk`

10. ZAP will use primarily two methods in order to scan a website, which of these two HTTP methods requests content?

	`GET`

11. Which option attempts to submit content to the website?

	`POST`
