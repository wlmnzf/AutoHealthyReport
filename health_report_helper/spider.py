# -*- coding: utf-8 -*-
#!/usr/bin/env python
# Copyright 2020 zhangt2333. All Rights Reserved.
# Author-Github: github.com/zhangt2333
# spider.py 2021/9/11 13:01
import json
import requests
import config
import logging

from uniform_login.uniform_login_spider import login
from uniform_login.uniform_login_spider import get_last_hs
import utils


def get_apply_list(cookies):
    try:
        response = requests.get(
            url='http://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/getApplyInfoList.do',
            headers=config.HEADERS,
            cookies=cookies
        )
        data = json.loads(response.text)
        return data['data']
    except Exception as e:
        logging.exception(e)
        raise e


def do_apply(cookies, WID, location,hssj):
    try:
        response = requests.get(
            url='http://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/saveApplyInfos.do',
            params=dict(
                WID=WID,
                IS_TWZC=1,
                IS_HAS_JKQK=1,
                JRSKMYS=1,
                JZRJRSKMYS=1,
                CURR_LOCATION=location,
                SFZJLN=0,
                ZJHSJCSJ=hssj
            ),
            headers=config.HEADERS,
            cookies=cookies
        )
        if not (response.status_code == 200 and '成功' in response.text):
            raise Exception('健康填报失败')
        logging.info("填报成功")
    except Exception as e:
        logging.exception(e)
        raise e


def main(config):
    username=config["username"]
    password=config["password"]
    hs_username=config["hs_username"]
    hs_password=config["hs_password"]
    # 登录
    logging.info(username)
    logging.info(password)
    cookies,response,driver,session = login(username, password, 'http://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/getApplyInfoList.do')
    tries=5
    while "CURR_LOCATION" not in response and tries>=0:
        driver.quit()
        session.close()
        logging.info("tries:"+str(5-tries))
        logging.info(response)
        cookies,response,driver,session=login(username, password, 'http://ehallapp.nju.edu.cn/xgfw/sys/yqfxmrjkdkappnju/apply/getApplyInfoList.do')
        tries-=1

    if "CURR_LOCATION" not in response:
         raise Exception("login error")
    # 获取填报列表
    apply_list = get_apply_list(cookies)
    if not apply_list[0]['TBRQ'] == utils.get_GMT8_str('%Y-%m-%d'):
        raise Exception("当日健康填报未发布")
    try:
        if apply_list[0].get('CURR_LOCATION') is not None:
            location = apply_list[0].get('CURR_LOCATION')
        elif apply_list[1].get('CURR_LOCATION') is not None:
            location = apply_list[1].get('CURR_LOCATION')
    except Exception as e:
        logging.exception(e, '取昨日地址错误, 请手动在App填报一次')
        raise e

    hssj=""
    try:
        res=get_last_hs(driver,hs_username,hs_password)
        hssj=res.split(":")[0]
    except Exception as e:
        logging.info("获取核酸时间失败！")
        logging.exception(e, '获取核酸时间失败')
        hssj="2022-04-15 15"

    # 填报当天
    do_apply(cookies, apply_list[0]['WID'], location,hssj)