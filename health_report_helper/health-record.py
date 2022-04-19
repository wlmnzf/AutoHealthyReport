import json
import random
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util import Padding
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

import config
import utils




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

def get_last_hs(driver,username_text,password_text):
    driver.get("https://user.www.gov.cn/sso/login")
    # loginname=driver.find_element_by_id("loginname")
    loginname=driver.find_element(by=By.ID, value="loginname")
    # password=driver.find_element_by_id("password")
    password=driver.find_element(by=By.ID, value="password")
    # login=driver.find_element_by_id("btn-login")
    login=driver.find_element(by=By.ID, value="btn-login")
    loginname.send_keys(username_text)
    password.send_keys(password_text)
    login.click()


    sleep(3)
    cookies=get_cookies(driver)
    session = requests.Session()
    session.cookies.update(cookies)


    driver.get("https://bmfw.www.gov.cn/xgbdhsktjcjgcx/index.html")
    sleep(3)
    # searchBtn=driver.find_element_by_id("searchBtn")
    searchBtn=driver.find_element(by=By.ID, value="searchBtn")
    searchBtn.click()
    sleep(3)
    # timestr=driver.find_element_by_class_name("jc-time").find_element_by_tag_name("span").text
    timestr=driver.find_element(by=By.CLASS_NAME, value="jc-time").find_element(by=By.TAG_NAME, value="span").text

    # print(timestr)
    # rd=random.random()
    # response_valid=session.get("https://user.www.gov.cn/js/valisign?servicecode=zfwfw&time=20180621112100&sign=3ae41655a0aaa1a5758aaa8310666337&domain=www.gov.cn&rd="+str(rd))
    # response_uid=session.get("https://user.www.gov.cn/js/islogin?servicecode=hsjycx&userinfo=false&getticket=false&rd="+str(rd))
    # response_ticket=session.get("https://user.www.gov.cn/js/islogin?servicecode=hsjycx&userinfo=false&getticket=true&rd="+str(rd))


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

def login(headers,username,password,config):
    url_login = r'https://authserver.nju.edu.cn/authserver/login'
    session = requests.Session()


    options = Options()
    options.add_argument('--headless')

    driver = webdriver.Chrome(options = options)
    driver.get(url_login)

    element = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.ID, "qr_img"))
        )

    sleep(5)


    # html = driver.find_element_by_xpath("//*").get_attribute("outerHTML")
    html=driver.find_element(by=By.XPATH, value="//*").get_attribute("outerHTML")
    # imgbase64=driver.find_element_by_id("captchaImg").screenshot_as_base64
    imgbase64=driver.find_element(by=By.ID, value="captchaImg").screenshot_as_base64


    request_url1 = "https://aip.baidubce.com/rest/2.0/ocr/v1/accurate_basic"
    request_url2 = "https://aip.baidubce.com/rest/2.0/ocr/v1/handwriting"
    
    verycode=get_verycode(request_url1,imgbase64,config)
    logging.info(verycode)
    logging.info("\n")
    if len(verycode)!=4:
        return "",driver,session

    cookies=get_cookies(driver)
    session.cookies.update(cookies)

    soup = BeautifulSoup(html, 'html.parser')
    soup.select_one("#pwdDefaultEncryptSalt").attrs['value']
    data_login = {
        'username': username, 
        'password': encryptAES(password, soup.select_one("#pwdDefaultEncryptSalt").attrs['value']),
        'captchaResponse':verycode,
        'lt' : soup.select_one('[name="lt"]').attrs['value'], 
        'dllt' : "userNamePasswordLogin",
        'execution' : soup.select_one('[name="execution"]').attrs['value'], 
        '_eventId' : soup.select_one('[name="_eventId"]').attrs['value'], 
        'rmShown' : soup.select_one('[name="rmShown"]').attrs['value'], 
    }

    response=session.post(url_login, data_login, headers=headers)
    return response.text,driver,session

def main(config):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

    username=config["username"]
    password=config["password"]
    response=""
    driver=""
    session=""

    try:
        response,driver,session=login(headers,username,password,config)

        tries=5
        while "账号登录" in response or not ("安全退出" in response or "个人资料" in response) and tries>=0:
            driver.quit()
            session.close()
            response,driver,session=login(headers,username,password,config)
            tries-=1
            logging.info("登录失败：正在进行第"+str(5-tries)+"次尝试\n")
            logging.info(response)


        if "账号登录" in response or not ("安全退出" in response or "个人资料" in response):
            raise Exception('登录失败!')
            logging.info("\n登录失败!")

        html = BeautifulSoup(response,'html.parser')
        Rname=html.find(name='div', attrs={'class': 'auth_username'}).find('span').find('span').string.replace("\r\n","").strip()
        logging.info(Rname+"登陆成功\n")
    
    except Exception as e:
        logging.exception(e)
        raise e

    entrys = json.loads(session.get("https://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/getApplyInfoList.do").text)["data"];
    lastAddr = "";
    for entry in entrys:
        if "CURR_LOCATION" in entry.keys() and len(entry["CURR_LOCATION"]) > 0:
            lastAddr = entry["CURR_LOCATION"];
            break

    print("签到地址：");
    print(lastAddr);
    print("\n")

    hssj=""
    try:
        hs_username=config["hs_username"]
        hs_password=config["hs_password"]
        res=get_last_hs(driver,hs_username,hs_password)
        hssj=res.split(":")[0]
    except:
        hssj="2022-04-15 15"

    print("上次核酸时间");
    print(hssj+":00");
    print("\n")

    entry = entrys[0];
    
    if "IS_TWZC" not in entry.keys():
        wid = entry["WID"];
        res =session.get("https://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/saveApplyInfos.do?WID="+wid+"&CURR_LOCATION="+lastAddr+"&ZJHSJCSJ="+hssj+"&SFZJLN=0&IS_TWZC=1&IS_HAS_JKQK=1&JRSKMYS=1&JZRJRSKMYS=1");
        print(json.loads(res.text)["msg"]);
    else:
        print("未执行操作");

    session.get("https://authserver.nju.edu.cn/authserver/logout");


if __name__ == '__main__':
    # if len(sys.argv) > 1:
    #     config.data = json.loads(sys.argv[1].replace("'", '"'))

    logging.info(config.data)
    

    if utils.get_GMT8_timestamp() > utils.str_to_timestamp(config.data['deadline'], '%Y-%m-%d'):
        logging.info("超出填报日期")
        exit(-1)

    random.seed(datetime.now())
    sleeptime=random.randint(1000,1500)
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
