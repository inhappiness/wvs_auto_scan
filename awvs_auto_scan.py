#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
#import xlrd
import xlwt
import json
import hashlib
import sys
import time

from requests.packages.urllib3.exceptions import InsecureRequestWarning
day=time.strftime("%Y-%m-%d",time.localtime(time.time()))
print(day)

def login_wvs(username,passwd): #登录并获取cookie和uisession
    hash_256 = hashlib.sha256()
    hash_str = "%s" % passwd
    hash_256.update(hash_str.encode('utf-8'))
    pwd_hash = hash_256.hexdigest()
    uname=username
    #print(pwd_hash)
    url='https://127.0.0.1:3443/api/v1/me/login'
    headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36','Content-Type': 'application/json;charset=UTF-8','Referer': 'https://127.0.0.1:3443/'}
    datas={"email":"%s" % uname,"password":"%s" % pwd_hash,"remember_me":"false"}
    s=json.dumps(datas)
    #print(s)
    requests.packages.urllib3.disable_warnings()
    r=requests.post(url=url,data=s,headers=headers,verify=False)
    x_auth=r.headers['X-Auth']
    c=r.headers['Set-cookie']
    c1=c.find(';')
    cookie=c[0:c1]
    #print(x_auth)
    #print(cookie)
    headers={'X-Auth':'%s' % x_auth,'cookie':'%s' % cookie,'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36','Content-Type': 'application/json;charset=UTF-8','Referer': 'https://127.0.0.1:3443/'}
    #print(headers)
    return headers

def add_target(files,headers):#添加扫描目标并返回target_id,以添加日期作为目标描述
    url='https://127.0.0.1:3443/api/v1/targets'
    headers=headers
    xld=xlrd.open_workbook(files)
    table=xld.sheet_by_index(0)
    nrows=table.nrows
    target_ids = []
    #print('address的行数为:%d' %nrows)
    for i in range(0,nrows):
        address=table.cell(i, 0).value
        d={"address":"%s" % address,"description":"%s" % day,"criticality":"10"}
        data=json.dumps(d)
        #print(data)
        r=requests.post(url=url,data=data,headers=headers,verify=False)
        d=json.loads(r.text)
        #print(d)
        target_id=d['target_id']
        target_ids.append(target_id)
    return target_ids
def start_job(target_ids,headers): #执行扫描任务
    l=len(target_ids)
    print(l)
    url = 'https://127.0.0.1:3443/api/v1/scans'
    headers = headers
    for i in range(0,l):
        d={"target_id":"%s" % target_ids[i],"profile_id":"11111111-1111-1111-1111-111111111111","report_template_id":"11111111-1111-1111-1111-111111111111","schedule":{"disable":False,"start_date":None,"time_sensitive":False}}
        data=json.dumps(d)
        print(data)
        requests.packages.urllib3.disable_warnings()
        r=requests.post(url=url,headers=headers,data=data,verify=False)
        print(r.text)

def get_current_target_ids(headers):#获取当前已经存在的待扫描目标ID
    current_target_ids=[]
    url='https://127.0.0.1:3443/api/v1/targets'
    for i in range(0,999):
        d = {'c': '%d' % i}
        requests.packages.urllib3.disable_warnings()
        s = requests.session()
        s.keep_alive = False
        r=requests.get(url=url,params=d,headers=headers,verify=False)
        data=json.loads(r.text)
        #print(d)
        t=data['targets']
        if t:
            t_value = t[0]
            current_target_id = t_value['target_id']
            # print(t)
            #print(t_value)
            #print(current_target_ids)
            current_target_ids.append(current_target_id)
        else:
            break
    return current_target_ids
def get_vulnerability(headers,current_target_ids):#获取漏洞信息
    w=1
    headers=headers
    l=len(current_target_ids)
    print(l)
    book = xlwt.Workbook(encoding="utf-8", style_compression=0)
    sheet = book.add_sheet("sheet1", cell_overwrite_ok=True)
    sheet.write(0, 0, "url")
    sheet.write(0, 1, "任务描述")
    sheet.write(0, 2, "最近一次发现时间")
    sheet.write(0, 3, "漏洞级别")
    sheet.write(0, 4, "漏洞名称")
    sheet.write(0, 5, "漏洞细节")
    sheet.write(0, 6, "CVE编号")

    for j in range(0,l):
        url = 'https://127.0.0.1:3443/api/v1/vulnerabilities?q=status:open;target_id:%s' % current_target_ids[j]
        requests.packages.urllib3.disable_warnings()
        s = requests.session()
        s.keep_alive = False
        r=requests.get(url=url,headers=headers,verify=False)
        d=json.loads(r.text)
        vuls=d['vulnerabilities']
        if vuls:
            l=len(vuls)
            for k in range(0,l):
                v=vuls[k]
                #print('该目标上的漏洞信息为：%s' % v)
                affects_url=v['affects_url']
                target_description=v['target_description']
                last_seen=v['last_seen']
                severity=v['severity']
                vt_name=v['vt_name']
                affects_detail=v['affects_detail']
                vt_cve=v['tags']
                sheet.write(w, 0, affects_url)
                sheet.write(w, 1, target_description)
                sheet.write(w, 2, last_seen)
                sheet.write(w, 3, severity)
                sheet.write(w, 4, vt_name)
                sheet.write(w, 5, affects_detail)
                sheet.write(w, 6, vt_cve)
                w +=1
    book.save("vul.xls")



if __name__ == '__main__':
    u = sys.argv[1]
    p = sys.argv[2]
    #print(u,p)
    headers = login_wvs(u,p)
    #target_ids=add_target('./wvs_url.xls',headers)
    #print(target_ids)
    #start_job(target_ids,headers)
    #current_target_ids=get_current_target_ids(headers)
    #print(current_target_ids)
    #l=len(current_target_ids)
    #print(l)
    print("1、从excel新导入扫描目标并执行扫任务请输入1后回车\r\n2、对已存在的目标重新执行扫描任务请输入2后回车\r\n3、获取扫描结果请输入3然后回车\r\n")
    choice=input(">")
    if choice=="1":
        headers = login_wvs(u, p)
        target_ids = add_target('./wvs_url.xls', headers)
        start_job(target_ids, headers)
    elif choice=="2":
        headers = login_wvs(u, p)
        current_target_ids = get_current_target_ids(headers)
        start_job(current_target_ids,headers)
    elif choice=="3":
        headers = login_wvs(u, p)
        current_target_ids = get_current_target_ids(headers)
        get_vulnerability(headers,current_target_ids)
    else:
        print("请输入1、2、3选择")