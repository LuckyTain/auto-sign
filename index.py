# -*- coding: utf-8 -*-
import smtplib
import sys
import json
import uuid
from email.mime.text import MIMEText
from email.header import Header
import hashlib
from Cryptodome.Cipher import AES


import oss2
import yaml
import base64
import requests
from pyDes import des, CBC, PAD_PKCS5
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning

# debug模式
debug = True
if debug:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 读取yml配置
def getYmlConfig(yaml_file='config.yml'):
    file = open(yaml_file, 'r', encoding="utf-8")
    file_data = file.read()
    file.close()
    config = yaml.load(file_data, Loader=yaml.FullLoader)
    return dict(config)


# 全局配置
config = getYmlConfig(yaml_file='config.yml')


# 获取当前utc时间，并格式化为北京时间
def getTimeStr():
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
    return bj_dt.strftime("%Y-%m-%d %H:%M:%S")


# 输出调试信息，并及时刷新缓冲区
def log(content):
    print(getTimeStr() + ' ' + str(content))
    sys.stdout.flush()


# 获取今日校园api
def getCpdailyApis(user):
    apis = {}
    user = user['user']
    schools = requests.get(url='https://mobile.campushoy.com/v6/config/guest/tenant/list', verify=not debug).json()[
        'data']
    flag = True
    for one in schools:
        if one['name'] == user['school']:
            if one['joinType'] == 'NONE':
                log(user['school'] + ' 未加入今日校园')
                exit(-1)
            flag = False
            params = {
                'ids': one['id']
            }
            res = requests.get(url='https://mobile.campushoy.com/v6/config/guest/tenant/info', params=params,
                               verify=not debug)
            data = res.json()['data'][0]
            joinType = data['joinType']
            idsUrl = data['idsUrl']
            ampUrl = data['ampUrl']
            if 'campusphere' in ampUrl or 'cpdaily' in ampUrl:
                parse = urlparse(ampUrl)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host

            ampUrl2 = data['ampUrl2']
            if 'campusphere' in ampUrl2 or 'cpdaily' in ampUrl2:
                parse = urlparse(ampUrl2)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host
            break
    if flag:
        log(user['school'] + ' 未找到该院校信息，请检查是否是学校全称错误')
        exit(-1)
    log(apis)
    return apis


# 登陆并获取session
def getSession(user, apis):
    user = user['user']
    params = {
        # 'login_url': 'http://authserverxg.swu.edu.cn/authserver/login?service=https://swu.cpdaily.com/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay',
        'login_url': apis['login-url'],
        'needcaptcha_url': '',
        'captcha_url': '',
        'username': user['username'],
        'password': user['password']
    }

    cookies = {}
    # 借助上一个项目开放出来的登陆API，模拟登陆
    res = ''
    try:
        res = requests.post(url=config['login']['api'], data=params, verify=not debug)
    except Exception as e:
        res = requests.post(url='http://127.0.0.1:8080/wisedu-unified-login-api-v1.0/api/login', data=params,
                            verify=not debug)

    # cookieStr可以使用手动抓包获取到的cookie，有效期暂时未知，请自己测试
    cookieStr = str(res.json()['cookies'])
    # log(cookieStr) 调试时再输出
    if cookieStr == 'None':
        log(res.json())
        exit(-1)
    # log(cookieStr)

    # 解析cookie
    for line in cookieStr.split(';'):
        name, value = line.strip().split('=', 1)
        cookies[name] = value
    session = requests.session()
    session.cookies = requests.utils.cookiejar_from_dict(cookies, cookiejar=None, overwrite=True)
    return session


# 获取最新未签到任务并全部签到
def getUnSignedTasksAndSign(session, apis, user):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    # 第一次请求每日签到任务接口，主要是为了获取MOD_AUTH_CAS
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay'.format(host=apis['host']),
        headers=headers, data=json.dumps({}), verify=not debug)
    # 第二次请求每日签到任务接口，拿到具体的签到任务
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay'.format(host=apis['host']),
        headers=headers, data=json.dumps({}), verify=not debug)
    if len(res.json()['datas']['unSignedTasks']) < 1:
        log('当前没有未签到任务')
        exit(-1)
    # log('AllTask: \n' + str(res.json()))
    for i in range(0, len(res.json()['datas']['unSignedTasks'])):
        # 出校扫码和入校扫码跳过
        if '出校' in res.json()['datas']['unSignedTasks'][i]['taskName']:
            continue
        if '入校' in res.json()['datas']['unSignedTasks'][i]['taskName']:
            continue
        # 只签每日健康打卡
        if not '健康打卡' in res.json()['datas']['unSignedTasks'][i]['taskName']:
            continue
        latestTask = res.json()['datas']['unSignedTasks'][i]
        params = {
            'signInstanceWid': latestTask['signInstanceWid'],
            'signWid': latestTask['signWid']
        }
        task = getDetailTask(session, params, apis)
        form = fillForm(task, session, user, apis)

        submitForm(session, user, form, apis)

#     新增功能: 请假情况下签到 leaveTasks
    for i in range(0, len(res.json()['datas']['leaveTasks'])):
        # 出校扫码和入校扫码跳过
        if '出校' in res.json()['datas']['leaveTasks'][i]['taskName']:
            continue
        if '入校' in res.json()['datas']['leaveTasks'][i]['taskName']:
            continue
        if not '健康打卡' in res.json()['datas']['leaveTasks'][i]['taskName']:
            continue
        latestTask = res.json()['datas']['leaveTasks'][i]
        params = {
            'signInstanceWid': latestTask['signInstanceWid'],
            'signWid': latestTask['signWid']
        }
        task = getDetailTask(session, params, apis)
        form = fillForm(task, session, user, apis)

        submitForm(session, user, form, apis)


# 获取签到任务详情
def getDetailTask(session, params, apis):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36 cpdaily/8.2.9 wisedu/8.2.9',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    res = session.post(
        url='https://{host}/wec-counselor-sign-apps/stu/sign/detailSignInstance'.format(host=apis['host']),
        headers=headers, data=json.dumps(params), verify=not debug)
    data = res.json()['datas']
    return data


# 填充表单
def fillForm(task, session, user, apis):
    user = user['user']
    form = {}
    if task['isPhoto'] == 1:
        fileName = uploadPicture(session, user['photo'], apis)
        form['signPhotoUrl'] = getPictureUrl(session, fileName, apis)
    else:
        form['signPhotoUrl'] = ''
    if task['isNeedExtra'] == 1:
        extraFields = task['extraField']
        defaults = config['cpdaily']['defaults']
        extraFieldItemValues = []
        for i in range(0, len(extraFields)):
            default = defaults[i]['default']
            extraField = extraFields[i]
            if config['cpdaily']['check'] and default['title'] != extraField['title']:
                log('第%d个默认配置项错误，请检查' % (i + 1))
                exit(-1)
            extraFieldItems = extraField['extraFieldItems']
            for extraFieldItem in extraFieldItems:
                if extraFieldItem['content'] == default['value']:
                    extraFieldItemValue = {'extraFieldItemValue': default['value'],
                                           'extraFieldItemWid': extraFieldItem['wid']}
                    # 其他，额外文本
                    if extraFieldItem['isOtherItems'] == 1:
                        extraFieldItemValue = {'extraFieldItemValue': default['other'],
                                               'extraFieldItemWid': extraFieldItem['wid']}
                    extraFieldItemValues.append(extraFieldItemValue)
        # log(extraFieldItemValues)
        # 处理带附加选项的签到
        form['extraFieldItems'] = extraFieldItemValues
    # form['signInstanceWid'] = params['signInstanceWid']
    form['signInstanceWid'] = task['signInstanceWid']
    form['longitude'] = user['lon']
    form['latitude'] = user['lat']
    form['isMalposition'] = task['isMalposition']
    form['abnormalReason'] = user['abnormalReason']
    form['position'] = user['address']
    form['uaIsCpadaily'] = True
    form['signVersion'] = '1.0.0'
    return form


# 上传图片到阿里云oss
def uploadPicture(session, image, apis):
    url = 'https://{host}/wec-counselor-sign-apps/stu/oss/getUploadPolicy'.format(host=apis['host'])
    res = session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps({'fileType': 1}),
                       verify=not debug)
    datas = res.json().get('datas')
    # log(datas)
    # new_api_upload
    fileName = datas.get('fileName') + '.png'
    accessKeyId = datas.get('accessid')
    xhost = datas.get('host')
    xdir = datas.get('dir')
    xpolicy = datas.get('policy')
    signature = datas.get('signature')
    # new_api_upload
    # new_api_upload2
    url = xhost + '/'
    data = {
        'key': fileName,
        'policy': xpolicy,
        'OSSAccessKeyId': accessKeyId,
        'success_action_status': '200',
        'signature': signature
    }
    data_file = {
        'file': ('blob', open(image, 'rb'), 'image/jpg')
    }
    res = session.post(url=url, data=data, files=data_file)
    if (res.status_code == requests.codes.ok):
        return fileName
    # new_api_upload2
    # log(res)
    return fileName
    return ''


# 获取图片上传位置
def getPictureUrl(session, fileName, apis):
    url = 'https://{host}/wec-counselor-sign-apps/stu/sign/previewAttachment'.format(host=apis['host'])
    data = {
        'ossKey': fileName
    }
    res = session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps(data), verify=not debug)
    photoUrl = res.json().get('datas')
    return photoUrl


# DES加密
def DESEncrypt(s, key='b3L26XNL'):
    key = key
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    encrypt_str = k.encrypt(s)
    return base64.b64encode(encrypt_str).decode()


# AES 加密
def AES_Encrypt(data, key='ytUQ7l2ZZu8mLvJZ'):
    data = data + (16 - len(data.encode()) % 16) * chr(16 - len(data.encode()) % 16)
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08\t\x01\x02\x03\x04\x05\x06\x07"
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv=iv)
    # 加密
    ciphertext = cipher.encrypt(data.encode("utf-8"))
    return base64.b64encode(ciphertext).decode()


# Sign 加密
def Sign_Encrypt(raw_sign_code_str):
    m = hashlib.md5()
    m.update(raw_sign_code_str.encode("utf-8"))
    sign = m.hexdigest()
    return sign


# 提交签到任务
def submitForm(session, user, form, apis):
    user = user['user']
    # Cpdaily-Extension
    extension = {
        "lon": user['lon'],
        "model": "MI 9",
        "appVersion": "9.0.12",
        "systemVersion": "11",
        "userId": user['username'],
        "systemName": "android",
        "lat": user['lat'],
        "deviceId": str(uuid.uuid1())
    }

    headers = {
        # 'tenantId': '1019318364515869',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 okhttp/3.12.4',
        'CpdailyStandAlone': '0',
        'extension': '1',
        'Cpdaily-Extension': DESEncrypt(json.dumps(extension)),
        'Content-Type': 'application/json; charset=utf-8',
        'Accept-Encoding': 'gzip',
        # 'Host': 'swu.cpdaily.com',
        'Connection': 'Keep-Alive'
    }
    extra_form = {
         "appVersion": "9.0.12",
         "systemName": "android",
         "bodyString": AES_Encrypt(json.dumps(form)),
         "sign": Sign_Encrypt(json.dumps(form)),  # New unused encryption
         "model": "MI 9",
         "lon": user['lon'],
         "calVersion": "firstv",
         "systemVersion": "11",
         "deviceId": str(uuid.uuid1()),
         "userId": user['username'],
         "version": "first_v2",
         "lat": user['lat']
         }
    res = session.post(url='https://{host}/wec-counselor-sign-apps/stu/sign/submitSign'.format(host=apis['host']),
                       headers=headers, data=json.dumps(extra_form), verify=not debug)
    message = res.json()['message']
    if message == 'SUCCESS':
        log('自动签到成功')
        # sendMessage('自动签到成功', user['email'])
        if config['notify']['success']:
            notify(user, message='今日校园签到成功')
    else:
        log('自动签到失败，原因是：' + message)
        # sendMessage('自动签到失败，原因是：' + message, user['email'])
        if config['notify']['fail']:
            notify(user, message='今日校园签到失败' + message)
        exit(-1)

# 通知功能
def notify(user, message):
    sendServerChan(user, message)
    sendTGBot(user, message)
    sendmail(msg=message, email=user['email'], subject='今日校园签到通知')


# 发送邮件
def sendmail(msg, email, subject):
    mail_host = config['smtp_mail']['host']
    mail_user = config['smtp_mail']['user']
    mail_pass = config['smtp_mail']['password']
    sender = config['smtp_mail']['sender']
    port = config['smtp_mail']['port']
    if mail_host is None or mail_user is None or mail_pass is None or sender is None or port is None or email is None:
        return
    receivers = email
    message = MIMEText(msg, 'plain', 'utf-8')
    message['From'] = Header(sender)
    message['To'] = Header(email, 'utf-8')
    # subject = '今日校园签到成功'
    message['Subject'] = Header(subject, 'utf-8')
    try:
        smtpObj = smtplib.SMTP()
        smtpObj.connect(mail_host, port)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, message.as_string())
        print("邮件发送成功")
    except smtplib.SMTPException:
        print("Error: 无法发送邮件")


# ServerChan推送
def sendServerChan(user, msg):
    try:
        ServerChan_Key = user['ServerChan']
        if ServerChan_Key is None:
            return
        url = 'https://sctapi.ftqq.com/' + ServerChan_Key + '.send'
        payload = {
            'title': msg,
            'desp': msg
        }
        requests.post(url=url, data=payload)
    except:
        print("Error: ServerChan推送失败")


# TGBot 推送
def sendTGBot(user, msg):
    TGBotToken = user['tgbot_token']
    ChatID = user['tgbot_chatid']
    if TGBotToken is None or ChatID is None:
        return
    try:
        url = 'https://api.telegram.org/bot' + str(TGBotToken) +  '/sendMessage'
        parm = {
            'chat_id': ChatID,
            'text': msg
        }
        requests.post(url, params=parm)
    except:
        print('Error: TGBot推送失败')

# 发送邮件通知
# def sendMessage(msg, email):
#     send = email
#     if msg.count("未开始") > 0:
#         return ''
#     try:
#         if send != '':
#             log('正在发送邮件通知。。。')
#             log(getTimeStr())
#             #               sendMessageWeChat(msg + getTimeStr(), '今日校园自动签到结果通知')
#
#             res = requests.post(url='http://www.zimo.wiki:8080/mail-sender/sendMail',
#                                 data={'title': '今日校园自动签到结果通知' + getTimeStr(), 'content': msg, 'to': send},
#                                 verify=not debug)
#             code = res.json()['code']
#             if code == 0:
#                 log('发送邮件通知成功。。。')
#             else:
#                 log('发送邮件通知失败。。。')
#             log(res.json())
#     except Exception as e:
#         log("send failed")


# 主函数
def main():
    for user in config['users']:
        apis = getCpdailyApis(user)
        session = getSession(user, apis)
        getUnSignedTasksAndSign(session, apis, user)


# 提供给腾讯云函数调用的启动函数
def main_handler(event, context):
    try:
        main()
    except Exception as e:
        raise e
    else:
        return 'success'


if __name__ == '__main__':
    # print(extension)
    print(main_handler({}, {}))
