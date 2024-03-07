---
title: "OhSINT - TryHackMe"
author: krishna
description: "Walkthrough of OhSINT from TryHackMe"
date: 2020-10-19 00:00:00 +0530
categories: [writeups, tryhackme]
tags: [osint]
---

**[OhSINT from TryHackMe](https://tryhackme.com/room/ohsint)**

## Task 1 - OhSINT

1. What is this users avatar of?

	running `strings WindowsXP.jpg | head -n 30` told me that there was exif data in it, so ran it with `exiftool` to curate and retrieve them properly

	![exif dump](/assets/img/tryhackme/ohsint/ohsint1.png)

	this told me that the author's name was probably **OWood Flint**, so a simple google search led to his:

	* [twitter account](https://twitter.com/owoodflint?lang=en)

	* [blog](https://oliverwoodflint.wordpress.com/author/owoodflint/)

	* [github project](https://github.com/OWoodfl1nt/people_finder)

	![twitter](/assets/img/tryhackme/ohsint/ohsint2.png)

	the twitter acccount had the profile picture of a `cat`

2. What city is this person in?

	from his tweets, he seems to have given the BSSID of his neighbour's wifi probably, so his location can also be acertained

	after creating an account on [wiggle](https://wigle.net/), an advanced search with the BSSID will give us more info

	![wiggle search](/assets/img/tryhackme/ohsint/ohsint3.png)

	on clicking the map hyperlink, we get to know he lives in `London`

	or just look at his [github project](https://github.com/OWoodfl1nt/people_finder)'s readme ;\_;

3. Whats the SSID of the WAP he connected to?

	`UnileverWiFi`

4. What is his personal email address?

	his [github project](https://github.com/OWoodfl1nt/people_finder)'s readme has his email id - `OWoodflint@gmail.com` in it

5. What site did you find his email address on?

	`Github`

6. Where has he gone on holiday?

	his [blog](https://oliverwoodflint.wordpress.com/author/owoodflint/) says that he has gone to `New York` on holiday.

7. What is this persons password?

	the source code of his post has the word `pennYDr0pper.!` in it, which matches the flag format

	![source code](/assets/img/tryhackme/ohsint/ohsint4.png)
