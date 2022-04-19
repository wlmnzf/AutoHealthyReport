# -*- coding: utf-8 -*-
#!/usr/bin/env python
# Copyright 2021 zhangt2333. All Rights Reserved.
# Author-Github: github.com/zhangt2333
# config.py 2021/9/11 13:01

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s\t%(levelname)s\t%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    # filename='../../../log/log.txt'
)

# The data you need to fill
# data = {
#     # fill them:
#     'username': 'fill-it',  # 学号
#     'password': 'fill-it',  # 密码
#     'deadline': '2021-10-05', # 填报截止日期，超过该天则停止填报并报错到 actions，开区间
#     'hs_username':"",
#     'hs_password':"",

#     'none': 'none'
# }

data ={
    'username': 'MF21140111', 
    'password': 'Whx123456',  
    'deadline': '2022-06-16',
    'hs_username':'15216678452',
    'hs_password':'Whx#2202',
    'appid':'25994502',
    'client_id':'Rw0BQxMCDDmQVKX8S7LvfOwO',
    'client_secret':'wbOh8FSzumpdcW7WkfmQtxz7LLUp4bY5'
}

# Don't edit this variables above
HEADERS = {
    "Host":"ehallapp.nju.edu.cn",
    "Connection":"keep-alive",
    "Accept":"application/json, text/plain, */*",
    "User-Agent":"Mozilla/5.0 (Linux; Android 6.0.1; k30pro Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.100 Mobile Safari/537.36  cpdaily/8.2.15 wisedu/8.2.15",
    "Referer":"http://ehallapp.nju.edu.cn/xgfw/sys/mrjkdkappnju/index.html",
    "Accept-Encoding":"gzip, deflate",
    "Accept-Language":"zh-CN,en-US;q=0.8",
    "X-Requested-With":"com.wisedu.cpdaily.nju",
}

