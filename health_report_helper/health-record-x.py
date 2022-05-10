from email import header
import json
import random
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util import Padding
from random import randint
from bs4 import BeautifulSoup
from time import sleep
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import base64
from datetime import datetime
import sys
import re
import sys
import logging
from io import BytesIO

import config
import utils

import urllib3

urllib3.disable_warnings()
session=""



def baiduocr(request_url,imgbase64,config):

    appid = config["appid"]
    client_id = config["client_id"]
    client_secret = config["client_secret"]

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

def get_verycode(request_url,imgbase64,config):
    res=baiduocr(request_url,imgbase64,config)
    return res

def get_cookies(driver):
    sel_cookies = driver.get_cookies()  #获取selenium侧的cookies
    jar = requests.cookies.RequestsCookieJar()  #先构建RequestsCookieJar对象
    for i in sel_cookies:
        jar.set(i['name'], i['value'],domain=i['domain'],path=i['path'])  
    return jar

def get_last_hs(username_text,password_text):
    options = Options()
    options.add_argument('--headless')

    driver = webdriver.Chrome(options = options)
    # driver.set_page_load_timeout(20)

    try:
        driver.get("https://user.www.gov.cn/sso/login")
    except Exception:
        driver.execute_script('window.stop()')

    # loginname=driver.find_element_by_id("loginname")
    loginname=driver.find_element(by=By.ID, value="loginname")
    # password=driver.find_element_by_id("password")
    password=driver.find_element(by=By.ID, value="password")
    # login=driver.find_element_by_id("btn-login")
    login=driver.find_element(by=By.ID, value="btn-login")
    loginname.send_keys(username_text)
    password.send_keys(password_text)
    login.click()

    # logging.info("axx")
    sleep(3)
    # cookies=get_cookies(driver)
    # session = requests.Session()
    # session.cookies.update(cookies)

    try:
        driver.get("https://bmfw.www.gov.cn/xgbdhsktjcjgcx/index.html")
    except Exception:
        driver.execute_script('window.stop()')

    sleep(3)
    # searchBtn=driver.find_element_by_id("searchBtn")
    searchBtn=driver.find_element(by=By.ID, value="searchBtn")
    searchBtn.click()
    sleep(3)
    # timestr=driver.find_element_by_class_name("jc-time").find_element_by_tag_name("span").text
    timestr=driver.find_element(by=By.CLASS_NAME, value="jc-time").find_element(by=By.TAG_NAME, value="span").text
    return timestr

def encryptAES(_p0: str, _p1: str) -> str:
        _chars = list('ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678')
        def _rds(len: int) -> str: 
            return ''.join(random.choices(_chars, k=len))
        def _gas(data: str, key0: str, iv0: str) -> bytes:
            encrypt = AES.new(key0.strip().encode('utf-8'), AES.MODE_CBC, iv0.encode('utf-8'))
            return base64.b64encode(encrypt.encrypt(Padding.pad(data.encode('utf-8'), 16)))
        return _gas(_rds(64) + _p0, _p1, _rds(16)).decode('utf-8')

def _unpad(s):
        return s;
        return s[48:-ord(s[len(s)-1:])];

def decrypt(m: str, key: str) -> str:
        m = base64.b64decode(m);
        iv = m[:AES.block_size];
        cipher = AES.new(key.strip().encode('utf-8'), AES.MODE_CBC, iv);
        return _unpad(cipher.decrypt(m[AES.block_size:])).decode('utf-8');

def needCaptcha(username):
    global session
    url = 'https://authserver.nju.edu.cn/authserver/needCaptcha.html?username={}'.format(
            username)
    r = session.post(url)
    if 'true' in r.text:
        return True
    else:
        return False

def getCaptchaCode():
    global session
    url = 'https://authserver.nju.edu.cn/authserver/captcha.html'
    res = session.get(url, stream=True)
    # img=BytesIO(res.content)
    # byte_data = byte_data.getvalue()# 从字节流管道中获取二进制
    base64_str = base64.b64encode(res.content).decode("ascii")# 二进制转base64
    return base64_str

def get_content_length(data):
    length = len(data.keys()) * 2 - 1
    total = ''.join(list(data.keys()) + list(data.values()))
    length += len(total)
    return length

def login(headers,username,password,config):
    url_login = r'https://authserver.nju.edu.cn/authserver/login'
    global session
    session = requests.Session()
    session.headers.update({
            'User-Agent': "Mozilla/5.0 (Linux; Android 11; M2006J10C Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/87.0.4280.141 Mobile Safari/537.36  cpdaily/8.2.7 wisedu/8.2.7})"
        })

    r = session.get(url_login)
    lt = re.search(
            r'<input type="hidden" name="lt" value="(.*)"/>', r.text).group(1)
    execution = re.search(
            r'<input type="hidden" name="execution" value="(.*)"/>', r.text).group(1)
    eventId = re.search(
            r'<input type="hidden" name="_eventId" value="(.*)"/>', r.text).group(1)
    rmShown = re.search(
            r'<input type="hidden" name="rmShown" value="(.*)"', r.text).group(1)
    pwdDefaultEncryptSalt = re.search(
            r'var pwdDefaultEncryptSalt = "(.*)"', r.text).group(1)

    
    verycode = ""
    if needCaptcha(username):
        imgbase64 = getCaptchaCode()
        request_url1 = "https://aip.baidubce.com/rest/2.0/ocr/v1/accurate_basic"
        request_url2 = "https://aip.baidubce.com/rest/2.0/ocr/v1/handwriting"
        verycode=get_verycode(request_url1,imgbase64,config)
        if len(verycode)!=4:
            return ""
    
    data = {
            'username': username,
            'password': encryptAES(password, pwdDefaultEncryptSalt),
            'lt': lt,
            'dllt': 'userNamePasswordLogin',
            'execution': execution,
            '_eventId': eventId,
            'rmShown': rmShown,
            'captchaResponse': verycode
        }
    headers["Content-Length"]=str(get_content_length(data))
    session.headers.update(headers)
    r = session.post(url_login, data=data, stream=True)

    headers = {
    "Host":"authserver.nju.edu.cn",
    "Connection":"keep-alive",
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "User-Agent":"Mozilla/5.0 (Linux; Android 10; BMH-AN20 Build/HUAWEIBMH-AN20; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.93 Mobile Safari/537.36 cpdaily/9.0.15 wisedu/9.0.15;",
    "Referer":"http://ehallapp.nju.edu.cn/xgfw/sys/mrjkdkappnju/index.html",
    "Accept-Encoding":"gzip, deflate, br",
    "Accept-Language":"zh-CN,zh;q=0.9",
    "X-Requested-With":"com.wisedu.cpdaily.nju",
    "Cache-Control":"max-age=0",
    "Content-Type":"application/x-www-form-urlencoded",
    "Origin":"https://authserver.nju.edu.cn",
    "Referer":"https://authserver.nju.edu.cn/authserver/login?service=http://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/getApplyInfoList.do",
    "sec-ch-ua":'" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"',
    "sec-ch-ua-mobile":"?0",
    "sec-ch-ua-platform":'"Linux"',
    "Sec-Fetch-Dest":"document",
    "Sec-Fetch-Mode":"navigate",
    "Sec-Fetch-Site":"none",
    "Sec-Fetch-User":"?1",
    "Upgrade-Insecure-Requests":"1",
}

    r= session.get("http://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/getApplyInfoList.do",headers=headers)
    return r.text
    

def main(config):
    
    headers = {
    "Cache-Control":"max-age=0",
    "Host":"ehallapp.nju.edu.cn",
    "Connection":"keep-alive",
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Encoding":"gzip, deflate, br",
    "Accept-Language":"zh-CN,zh;q=0.9",
    "User-Agent":"Mozilla/5.0 (Linux; Android 10; BMH-AN20 Build/HUAWEIBMH-AN20; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.93 Mobile Safari/537.36 cpdaily/9.0.15 wisedu/9.0.15",
    "Sec-Fetch-Dest":"document",
    "Sec-Fetch-Mode":"navigate",
    "Sec-Fetch-Site":"same-origin",
    "Sec-Fetch-User":"?1",
    "Upgrade-Insecure-Requests":"1",
    "Content-Type":"application/x-www-form-urlencoded",
}
    username=config["username"]
    password=config["password"]

    jsontext=""

    try:
        jsontext=login(headers,username,password,config)

        tries=5
        while "CURR_LOCATION" not in jsontext  and tries>=0:
            sleep(5)
            tries-=1
            logging.info("登录失败：正在进行第"+str(5-tries)+"次尝试\n")
            logging.info(jsontext)
            jsontext=login(headers,username,password,config)
            
        if "CURR_LOCATION" not in jsontext:
            raise Exception('登录失败!')
            logging.info("\n登录失败!")

        logging.info("登陆成功\n")
    
    except Exception as e:
        logging.exception(e)
        raise e

    entrys = json.loads(jsontext)["data"];
    lastAddr = "";
    hssj=""
    for entry in entrys:
        if "CURR_LOCATION" in entry.keys() and len(entry["CURR_LOCATION"]) > 0:
            lastAddr = entry["CURR_LOCATION"];
        if "ZJHSJCSJ" in entry.keys() and len(entry["ZJHSJCSJ"]) > 0:
            hssj=entry["ZJHSJCSJ"]
        if lastAddr !="" and hssj!="":
            break

    logging.info("签到地址：");
    logging.info(lastAddr);
    logging.info("\n")

    try:
        hs_username=config["hs_username"]
        hs_password=config["hs_password"]
        res=get_last_hs(hs_username,hs_password)
        hssj=res.split(":")[0]
    except Exception as e:
        logging.info(e)
        logging.info("获取最新核酸时间失败，本次采用历史核酸时间！");
        

    logging.info("上次核酸时间");
    logging.info(hssj+":00");
    logging.info("\n")

    entry = entrys[0];
    

    global session

    HEADERS = {
    "Host":"ehallapp.nju.edu.cn",
    "Connection":"keep-alive",
    "Accept":"application/json, text/plain, */*",
    "User-Agent":"Mozilla/5.0 (Linux; Android 10; BMH-AN20 Build/HUAWEIBMH-AN20; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.93 Mobile Safari/537.36 cpdaily/9.0.15 wisedu/9.0.15;",
    "Referer":"http://ehallapp.nju.edu.cn/xgfw/sys/mrjkdkappnju/index.html",
    "Accept-Encoding":"gzip, deflate",
    "Accept-Language":"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "X-Requested-With":"com.wisedu.cpdaily.nju",
}



    USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 10; BMH-AN20 Build/HUAWEIBMH-AN20; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.93 Mobile Safari/537.36 cpdaily/9.0.15 wisedu/9.0.15;",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 (4463142912)cpdaily/9.0.14  wisedu/9.0.14",
    "Mozilla/5.0 (Linux; Android 6.0.1; Mate 10 Pro Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.158 Mobile Safari/537.36 cpdaily/9.0.14  wisedu/9.0.14;",
    "Mozilla/5.0 (Linux; Android 6.0.1; oppo R11s Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.158 Mobile Safari/537.36 cpdaily/9.0.15 wisedu/9.0.15;",
    "Mozilla/5.0 (Linux; Android 6.0.1; oneplus 5 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.158 Mobile Safari/537.36 cpdaily/9.0.15 wisedu/9.0.15;",
    ]

    random_agent = USER_AGENTS[randint(0, len(USER_AGENTS)-1)]
    # random_agent = USER_AGENTS[4]
    HEADERS["User-Agent"] = random_agent

    requests.packages.urllib3.disable_warnings
    if "IS_TWZC" not in entry.keys():
        wid = entry["WID"];
        res =session.get("https://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/saveApplyInfos.do?WID="+wid+"&CURR_LOCATION="+lastAddr+"&ZJHSJCSJ="+hssj+"&SFZJLN=0&IS_TWZC=1&IS_HAS_JKQK=1&JRSKMYS=1&JZRJRSKMYS=1",headers=HEADERS,verify=False);
        logging.info(json.loads(res.text)["msg"]);
    else:
        logging.info("未执行操作");



if __name__ == '__main__':
    if len(sys.argv) > 1:
        config.data = json.loads(sys.argv[1].replace("'", '"'))

    if utils.get_GMT8_timestamp() > utils.str_to_timestamp(config.data['deadline'], '%Y-%m-%d'):
        logging.info("超出填报日期")
        exit(-1)

    random.seed(datetime.now())
    sleeptime=random.randint(500,1000)
    print("==========================================")
    logging.info("启动时间")
    logging.info (utils.get_GMT8_str("%Y-%m-%d %H:%M:%S")) 
    logging.info("\n")

    logging.info("延时:")
    logging.info(str(sleeptime)+"s")
    # time.sleep(sleeptime)
    logging.info("\n")

    logging.info("工作时间:")
    logging.info (utils.get_GMT8_str("%Y-%m-%d %H:%M:%S")) 
    logging.info("\n")

    logging.info("当前用户:")
    logging.info (config.data["username"]) 
    logging.info("\n")

    main(config.data);
    print("==========================================")
