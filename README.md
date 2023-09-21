# What is this about
This is a script I made which scrapes the web using dorks to find domains that still use vulnerable versions of the phpThumb php script.

# What is phpThumb
phpThumb is basically a PHP script that provides image resizing, cropping, and manipulation capabilities for web applications when loading images basically. It is often used as a server-side image processing solution to generate thumbnails, resize images, apply filters, and perform other image-related tasks dynamically.

# Vulns
Turns out specific versions of this php script are vulnerable to RCE and SSRF. Specifically:
- versions ranging from 1.7.9 and bellow are vulnerable to **RCE** (CVE-2010-1598).
- version 1.7.12 is vulnerable to **SSRF** (CVE-2013-6919).

# Output example
Running the script we get a table with some of the domains found, their phpThumb versions (if found) and the vulnerability that they probably have:
![image](https://github.com/connar/phpThumb/assets/87579399/0eb91b85-b8d1-4fa7-97f2-9a61cf8e720a)

