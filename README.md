# HackTheBox_Busqueda

![](BoxImage.png)

## Box Summary

Busqueda is an easy difficulty Linux machine that involves exploiting a vulnerability in a resource on the web server, 'Searchor 2.4.0'. This vulnerability allows for arbitrary code execution due to the direct insertion of unsanitized query parameters into the python eval() function. This vulnerability has no proof of concept, so we are left to forge our own payload to exploit Searchor's usage of the python eval() function. Arbitrary code execution is leveraged to gain user level access on the machine, upon which enumeration reveals a configuration file with credentials for the user. Leveraging credentials, it is discovered that the user can use sudo to run a custom script as root. The custom script, while source code is unavailable, is discovered to be vulnerable to path injection due to a lack of using an absolute path to reference a second custom script. This allows us to craft our own malicious version of the poorly referenced script, granting us access as the root user.

## Link to Writeup

[Full Busqueda Writeup](https://github.com/0xColonelPanic/HackTheBox_Busqueda/blob/main/Busqueda.md)
