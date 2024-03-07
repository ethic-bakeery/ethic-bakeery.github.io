---
title: "Pickle Rick - TryHackMe"
author: krishna
description: "Walkthrough of Pickle Rick from TryHackMe"
date: 2020-10-21 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [web, linux, privesc, ctf]
---

**[Pickle Rick from TryHackMe](https://tryhackme.com/room/picklerick)**

the description says that there is a web server up and running, so we go to the IP

![homepage](/assets/img/tryhackme/picklerick/picklerick1.png)

so we have to ssh into the system and get the ingredients

the source code of the page tells us that the username is `R1ckRul3s`

![source code](/assets/img/tryhackme/picklerick/picklerick2.png)

ok, i was wrong because ssh gave me this

```terminal
$ ssh R1ckRul3s@10.10.145.211
R1ckRul3s@10.10.145.211: Permission denied (publickey).
```

and gobuster gave me this

```terminal
$ gobuster dir -u http://10.10.145.211 -w /usr/share/wordlists/dirb/common.txt -x .php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.145.211
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/10/21 22:41:54 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/assets (Status: 301)
/denied.php (Status: 302)
/index.html (Status: 200)
/login.php (Status: 200)
/portal.php (Status: 302)
/robots.txt (Status: 200)
/server-status (Status: 403)
===============================================================
2020/10/21 22:44:31 Finished
===============================================================
```

so, `robots.txt` contains just `Wubbalubbadubdub`.

```terminal
$ curl http://10.10.145.211/robots.txt
Wubbalubbadubdub
```

so this might be the password to the login portal.

it works! we are faced with a command execution portal where we can't use any display commands strangely

and all other tabs are inaccessible with a denied message

so, i tried for a reverse shell with bash first, but that didn't work. so i went ahead with perl and it worked. [commands](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

here, i could use all commands and even more!

![privs](/assets/img/tryhackme/picklerick/picklerick3.png)

so, i `cat`-ed the contents of `Sup3rS3retPickl3Ingred.txt` for the 1st ingredient

![first ingredient](/assets/img/tryhackme/picklerick/picklerick4.png)

there was another file of interest named `clue.txt` that said

```terminal
$ curl http://10.10.145.211/clue.txt
Look around the file system for the other ingredient.
```

so, i ran `find`, `grep`-ing for `ingredient` and i found the second ingredient in `/home/rick/second\ ingredient`

![second ingredient literally](/assets/img/tryhackme/picklerick/picklerick5.png)

from previous experience, i searched `/root` and luckily found the 3rd flag there!

![final ingredient](/assets/img/tryhackme/picklerick/picklerick6.png)

overall, nice short CTF and v nice R&M refs
