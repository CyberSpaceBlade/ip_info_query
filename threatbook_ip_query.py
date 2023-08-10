import pandas
import requests
import time

import xlwt
from requests.adapters import HTTPAdapter
import random

# 设置超时重连
s = requests.Session()
s.mount('http://', HTTPAdapter(max_retries=3))
s.mount('https://', HTTPAdapter(max_retries=3))

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; 360SE)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
    "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b13pre) Gecko/20110307 Firefox/4.0b13pre",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:16.0) Gecko/20100101 Firefox/16.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
    "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
]

url = "https://api.threatbook.cn/v3/scene/ip_reputation"

headers = {"User-Agent": random.choice(USER_AGENTS)}  # 随机UA


def single_ip_test(ip, input_header):  # 单一IP测试，返回获得json
    params = {
        # "apikey": "a66d0f72d82e40b58c1b79849ef9c4326d7806aba0a9459e99bb1e1b4d56b8fa", 我大号
        # "apikey": "c708d7f506f44920b990e090db67b7ef281ef646f47446ec881670721f1cc129", 我小号
        # 使用时请设定自己的apikey并严格控制好待查询的IP数量
        "resource": ip  # 测试IP
    }
    response = s.get(url, params=params, headers=input_header, timeout=3)
    # print(response.json())
    get_result = response.json()
    return get_result


def model_1(ip, input_header):  # 单个Ip测试并输出结果
    get_result = single_ip_test(ip, input_header)
    ip, is_malicious, severity, judgments, location = print_res(ip, get_result)
    return ip, is_malicious, severity, judgments, location


def print_res(ip, get_result):  # 输出单个IP结果
    print("-" * 30, "查询结果如下", "-" * 30)
    print("IP", "\t" * 5, "是否为恶意IP", "\t", "风险等级", "\t", "威胁类型", "\t" * 3, "定位")

    is_malicious = get_result['data']['{}'.format(ip)]['is_malicious']
    severity = get_result['data']['{}'.format(ip)]['severity']
    judgments = get_result['data']['{}'.format(ip)]['judgments']
    country = get_result['data']['{}'.format(ip)]['basic']['location']['country']
    province = get_result['data']['{}'.format(ip)]['basic']['location']['province']  # 查IP归属省份
    city = get_result['data']['{}'.format(ip)]['basic']['location']['city']  # 查IP归属城市
    # 将IP归属的国家、省份、城市合并成一个字符串
    location = country + '-' + province + '-' + city

    print(ip, "\t" * 2, is_malicious, "\t" * 3, severity, "\t" * 2, judgments, "\t", location)
    return ip, is_malicious, severity, judgments, location


def model_2(excel_name, input_header):
    df = pandas.read_excel(excel_name)
    column_data = df['IP']
    IP_list = list(dict(column_data).values())

    excelname = 'Excel-IP信息汇总.xlsx'
    file_excel = xlwt.Workbook(encoding='utf-8', style_compression=0)
    sheet = file_excel.add_sheet('ip_query_res')
    sheet.write(0, 0, 'IP')
    sheet.write(0, 1, '是否为恶意IP')
    sheet.write(0, 2, '风险等级')
    sheet.write(0, 3, '威胁类型')
    sheet.write(0, 4, '定位')

    count = 1
    for ip in IP_list:
        ip, is_malicious, severity, judgments, location = model_1(ip, input_header)
        sheet.write(count, 0, ip)
        sheet.write(count, 1, is_malicious)
        sheet.write(count, 2, severity)
        sheet.write(count, 3, judgments)
        sheet.write(count, 4, location)
        count = count + 1
        time.sleep(1)  # 防止触发规则
    file_excel.save(excelname)
    print("Excel-IP信息表写入完成！")


def model_3(txt_name, input_header):
    file = open(txt_name, "r")
    IP_list = file.readlines()

    excelname = 'Txt-IP信息汇总.xlsx'
    file_excel = xlwt.Workbook(encoding='utf-8', style_compression=0)
    sheet = file_excel.add_sheet('ip_query_res')
    sheet.write(0, 0, 'IP')
    sheet.write(0, 1, '是否为恶意IP')
    sheet.write(0, 2, '风险等级')
    sheet.write(0, 3, '威胁类型')
    sheet.write(0, 4, '定位')

    count = 1
    for ip in IP_list:
        ip = ip.split("\n")[0]
        if ip != "":  # readlines最后一行就是换行符，分完以后就是空的，这样就直接扔掉，避免浪费
            ip, is_malicious, severity, judgments, location = model_1(ip, input_header)
            sheet.write(count, 0, ip)
            sheet.write(count, 1, is_malicious)
            sheet.write(count, 2, severity)
            sheet.write(count, 3, judgments)
            sheet.write(count, 4, location)
            count = count + 1
            time.sleep(1)  # 防止触发规则
    file_excel.save(excelname)
    print("Txt-IP信息表写入完成！")


def main():
    print("-" * 30, "微步IP查询工具开始工作啦！", "-" * 30)
    header_ua_model = input("请选择User-agent设定模式,1为固定UA,2为动态随机UA(默认为2):")
    if header_ua_model == 1:
        input_header = ('{"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, '
                        'like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER"}')
    else:
        input_header = '{"User-Agent": random.choice(USER_AGENTS)} '  # 随机UA
    input_header = eval(input_header)

    work_model = int(input("请选择IP查询模式,1为查询单个IP,2为导入excel表格,3为导入txt:"))
    if work_model == 1:
        test_ip = input("请输入查询IP:")
        # test_ip = "47.93.34.185"
        # test_ip = "101.82.127.217"
        model_1(test_ip, input_header)
    elif work_model == 2:
        excel_name = input("请输入excel文件名:")
        # excel_name = "test_excel.xlsx"
        model_2(excel_name, input_header)
    elif work_model == 3:
        txt_name = input("请输入txt文件名:")
        # txt_name = "test_txt.txt"
        model_3(txt_name, input_header)

    print("-" * 30, "微步IP查询工具工作完成啦！", "-" * 30)


if __name__ == "__main__":
    main()
