# -*- coding: utf-8 -*-
# !/usr/bin/env python
# Copyright 2021 zhangt2333. All Rights Reserved.
# Author-Github: github.com/zhangt2333
# uniform_login_spider.py 2021/9/11 13:01
import base64
import random
import re
import json

import requests
from Cryptodome.Cipher import AES

import json
from time import sleep
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def get_last_hs(username_text,password_text):
    options = Options()
    options.add_argument('--headless')
    options.add_argument('user-agent=%s'%HEADERS_LOGIN)
    driver = webdriver.Chrome(options = options)
    driver.set_page_load_timeout(10)
    driver.get("https://user.www.gov.cn/sso/login")

    element = WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.ID, "qr"))
            )

    sleep(5)


    loginname=driver.find_element_by_id("loginname")
    password=driver.find_element_by_id("password")
    login=driver.find_element_by_id("btn-login")
    loginname.send_keys(username_text)
    password.send_keys(password_text)
    login.click()


    sleep(5)
    driver.get("https://bmfw.www.gov.cn/xgbdhsktjcjgcx/index.html")
    element = WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.ID, "showname"))
            )
    sleep(5)

    searchBtn=driver.find_element_by_id("searchBtn")
    searchBtn.click()
    sleep(3)
    timestr=driver.find_element_by_class_name("jc-time").find_element_by_tag_name("span").text
    print(timestr)
    return timestr

def baiduocr(request_url,imgbase64):

    appid = "25994502"
    client_id = "Rw0BQxMCDDmQVKX8S7LvfOwO"
    client_secret = "wbOh8FSzumpdcW7WkfmQtxz7LLUp4bY5"

    token_url = "https://aip.baidubce.com/oauth/2.0/token"
    host = f"{token_url}?grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}"

    response = requests.get(host)
    access_token = response.json().get("access_token")


    # 调用通用文字识别高精度版接口
    # request_url = "https://aip.baidubce.com/rest/2.0/ocr/v1/accurate_basic"
    # request_url = "https://aip.baidubce.com/rest/2.0/ocr/v1/handwriting"
    

    body = {
        "image": imgbase64,
        "language_type": "auto_detect",
        "detect_direction": "true",
        "paragraph": "true",
        "probability": "true",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    request_url = f"{request_url}?access_token={access_token}"
    response = requests.post(request_url, headers=headers, data=body)
    content = response.content.decode("UTF-8")
    # 打印调用结果
    content=json.loads(content)
    res=""
    if len(content["words_result"])>0:
        res=content["words_result"][0]["words"].strip().replace(" ","")
    return res

def get_verycode(request_url,imgbase64):
    res=baiduocr(request_url,imgbase64)
    return res

def get_cookies(driver):
    sel_cookies = driver.get_cookies()  #获取selenium侧的cookies
    jar = requests.cookies.RequestsCookieJar()  #先构建RequestsCookieJar对象
    for i in sel_cookies:
        jar.set(i['name'], i['value'],domain=i['domain'],path=i['path'])  
    return jar

def password_encrypt(text: str, key: str):
    """translate from encrypt.js"""
    _rds = lambda length: ''.join([random.choice('ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678') for _ in range(length)])
    pad = lambda s: s + (len(key) - len(s) % len(key)) * chr(len(key) - len(s) % len(key))
    text = pad(_rds(64) + text).encode("utf-8")
    aes = AES.new(str.encode(key), AES.MODE_CBC, str.encode(_rds(16)))
    return str(base64.b64encode(aes.encrypt(text)), 'utf-8')


# example: login(username='your-student-id', password='your-password', to_url='https://ehall.nju.edu.cn:443/login?service=https://ehall.nju.edu.cn/ywtb-portal/official/index.html')
def login(username, password, to_url):
    """登录并返回JSESSIONID"""
    url = 'https://authserver.nju.edu.cn/authserver/login?service=' + to_url
    lt, dllt, captchaResponse,execution, _eventId, rmShown, pwdDefaultEncryptSalt, cookies,driver = getLoginCasData(url)

    if len(captchaResponse)!=4:
        # driver.quit()
        return cookies,"",driver,""


    data = dict(
        username=username,
        password=password_encrypt(password, pwdDefaultEncryptSalt),
        lt=lt,
        captchaResponse=captchaResponse,
        dllt=dllt,
        execution=execution,
        _eventId=_eventId,
        rmShown=rmShown,
    )
    try:
        s=requests.session()
        s.keep_alive=False
        s.cookies.update(cookies)
        response = s.post(
            url=url,
            headers=HEADERS_LOGIN,
            data=data
        )
        for resp in response.history:
            if resp.cookies.get('MOD_AUTH_CAS'):
                return resp.cookies,response.text,driver,s
        if response.cookies.get('JSESSIONID'):
            return response.cookies,response.text,driver,s
        # raise Exception("login error")
        return response.cookies,response.text,driver,s
    except execution as e:
        raise e


def getLoginCasData(url):
    """返回CAS数据和初始JSESSIONID"""
    try:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('user-agent=%s'%HEADERS_LOGIN)
        driver = webdriver.Chrome(options = options)
        driver.get(url)

        element = WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.ID, "qr_img"))
            )

        sleep(5)


        html = driver.find_element_by_xpath("//*").get_attribute("outerHTML")

        imgbase64=driver.find_element_by_id("captchaImg").screenshot_as_base64

        request_url1 = "https://aip.baidubce.com/rest/2.0/ocr/v1/accurate_basic"
        request_url2 = "https://aip.baidubce.com/rest/2.0/ocr/v1/handwriting"

        verycode=get_verycode(request_url1,imgbase64)

        cookies=get_cookies(driver)
        # session.cookies.update(cookies)

        lt = re.findall('name="lt" value="(.*?)"', html)[1]
        dllt = re.findall('name="dllt" value="(.*?)"', html)[1]
        captchaResponse=verycode
        execution = re.findall('name="execution" value="(.*?)"', html)[1]
        eventId = re.findall('name="_eventId" value="(.*?)"', html)[1]
        rmShown = re.findall('name="rmShown" value="(.*?)"', html)[1]
        pwdDefaultEncryptSalt = re.findall('id="pwdDefaultEncryptSalt" value="(.*?)"', html)[0]
        return lt, dllt,captchaResponse, execution, eventId, rmShown, pwdDefaultEncryptSalt, cookies,driver
    except Exception as e:
        raise e


HEADERS_LOGIN = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
}
