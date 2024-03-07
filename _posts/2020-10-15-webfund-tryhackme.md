---
title: "Web Fundamentals - TryHackMe"
author: krishna
description: "Walkthrough of Web Fundamentals from TryHackMe"
date: 2020-10-15 22:22:22 +0530
categories: [writeups, tryhackme]
tags: [web]
---

**[Web Fundamentals from TryHackMe](https://tryhackme.com/room/webfundamentals)**

## Task 1 - Introduction and Objectives

eh, generic intro stuff

## Task 2 - How do we load websites?

1. What request verb is used to retrieve page content?

    `GET`

2. What port do web servers normally listen on?

    `80`

3. What's responsible for making websites look fancy?

    `CSS`

## Task 3 - More HTTP - Verbs and request formats

1. What verb would be used for a login?

    `POST`

2. What verb would be used to see your bank balance once you're logged in?

    `GET`

3. Does the body of a GET request matter? Yea/Nay

    `Nay`

4. What's the status code for "I'm a teapot"?

    `418`

5. What status code will you get if you need to authenticate to access some content, and you're unauthenticated?

    `401`

## Task 4 - Cookies, tasty!

intro to cookies

## Task 5 - Mini CTF

not going to post the flags here, instead the commands i used to obtain them (basically what a write-up is)

1. What's the GET flag?

    `curl $MACHINE_IP/ctf/get`

2. What's the POST flag?

    `curl -X POST -d "flag_please" $MACHINE_IP/ctf/post`

    `-X` for the **request type** and `-d` for the **data to be sent in POST reqs**

3. What's the "Get a cookie" flag?

    `curl -c outcookie.txt $MACHINE_IP/ctf/getcookie`

    `-c` for saving the cookies received 

then check `outcookie.txt` for the flag

4. What's the "Set a cookie" flag?

    `curl -b "flagpls=flagpls" $MACHINE_IP/ctf/sendcookie`

    `-b` for setting the cookies to be used
