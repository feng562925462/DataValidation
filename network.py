# coding=utf-8

import sys
import json
from decimal import Decimal as D
import shutil
import os
from urllib.parse import urlparse
from socket import gethostbyname

'''
    该py暂时执行的结果：
    解析log中所有的TimingData，
    对upload中的数据进行误差校正
    根据upload上报数据进行对应的指标进行校验

    注意：
        1.该文件由python3编写，建议用python3执行
        2.如果待解析内容超过2.56MB，
            请使用 python3 ./timmingData.py >2.txt，导出新的文件，
            否则控制台输出不完全，解决办法见(https://blog.csdn.net/qq_36303970/article/details/87544790)
        3.默认使用py当前文件夹下的1.txt文件，如需更改可指定路径
            例：python3 ./timmingData.py /Users/love/PycharmProjects/test/1.txt >2.txt
'''


# 解析一段TimingData原始数据为字典
def analysisTimingData(list):
    temp_dict = {
        "url": "0",
        "time": "0",
        "ResponseBodyBytesDecoded": "0",
        "TotalBytesReceived": "0",
        "LocalAddressAndPort": "0",
        "RemoteAddressAndPort": "0",
        "RequestHeaderSize": "0",
        "SecureConnectionStart": "0",
        "ResponseHeaderSize": "0",
        "TimingDataInit": "0",
        "NetworkProtocolName": "0",
        "ConnectionInterfaceIdentifier": "0",
        "ResponseStart": "0",
        "ResponseBodyBytesReceived": "0",
        "ConnectionUUID": "0",
        "DomainLookupStart": "0",
        "FetchStart": "0",
        "DomainLookupEnd": "0",
        "RequestEnd": "0",
        "ConnectionReused": "0",
        "RequestStart": "0",
        "ResponseEnd": "0",
        "TotalBytesSent": "0",
        "ConnectEnd": "0",
        "ConnectStart": "0",
        "SecureConnectionEnd": "0"
    }
    for str in list:
        if '---' in str:
            continue

        content = str.split("[TimingData] ")[1]
        array = content.split(":", 1)
        if '{' in array[1]:
            continue

        temp_dict[array[0]] = array[1]

    return temp_dict


# 计算差值，对小数点保留一位精确度
def differenceValue(f1, f2, isChange=True):
    result = D(f1) - D(f2)
    if isChange == True:
        result *= 1000000
    return round(result, 1)


# 和计算
def sum(f1, f2, isChange=False):
    result = D(f1) + D(f2)
    if isChange == True:
        result *= 1000000
    return round(result, 1)


# 提取TimingData中的数据指标
def extractionIndexTimingData(dict):
    temp_dict = {}
    temp_dict["ru"] = dict.get("url")

    dns = dnsAnalysis(temp_dict["ru"])
    temp_dict['cna'] = dns[0]
    if len(temp_dict['cna']) > 0:
        temp_dict['lc'] = temp_dict['cna'][-1]
    else:
        temp_dict['lc'] = ''

    print(dict)
    print(dict.get("RemoteAddressAndPort"))

    address = dict.get("RemoteAddressAndPort")

    if address:
        if ':.' in address:
            temp_dict["tp"] = address.split(":.")[1]
            temp_dict["tip"] = address.split(":.")[0]
        elif ':' in address:
            temp_dict["tp"] = address.split(":")[1]
            temp_dict["tip"] = address.split(":")[0]
        else:
            if temp_dict["ru"].startswith('https'):
                temp_dict["tp"] = 443
            else:
                temp_dict["tp"] = 80
            temp_dict["tip"] = address

    temp_dict["st"] = differenceValue(dict.get("time"),
                                      differenceValue(dict.get("ResponseEnd"), dict.get("FetchStart")), False)

    temp_dict["dt"] = differenceValue(dict.get("DomainLookupEnd"), dict.get("DomainLookupStart"))

    temp_dict["ct"] = differenceValue(dict.get("ConnectEnd"), dict.get("ConnectStart"))

    SecureConnectionEnd = float(dict.get("SecureConnectionEnd"))
    SecureConnectionStart = float(dict.get("SecureConnectionStart"))
    if SecureConnectionEnd != 0 and SecureConnectionStart != 0:
        temp_dict["sti"] = differenceValue(dict.get("SecureConnectionEnd"), dict.get("SecureConnectionStart"))
    elif SecureConnectionEnd == 0 and SecureConnectionStart != 0:
        temp_dict["sti"] = differenceValue(dict.get("ConnectEnd"), dict.get("SecureConnectionStart"))
    else:
        temp_dict["sti"] = 0

    temp_dict["rt"] = differenceValue(dict.get("RequestEnd"), dict.get("RequestStart"))

    temp_dict["rti"] = differenceValue(dict.get("ResponseStart"), dict.get("RequestEnd"))

    temp_dict["dti"] = differenceValue(dict.get("ResponseEnd"), dict.get("ResponseStart"))

    temp_dict["si"] = 0
    temp_dict["li"] = 0
    temp_dict["lp"] = 0
    temp_dict["et"] = temp_dict["st"] + temp_dict["rt"]
    temp_dict["rh"] = 0
    temp_dict["rd"] = sum(dict.get("TotalBytesSent"), dict.get("RequestHeaderSize"))
    temp_dict["rhe"] = ''
    temp_dict["rds"] = sum(dict.get("TotalBytesReceived"), dict.get("ResponseHeaderSize"))
    temp_dict["ei"] = 0
    temp_dict["se"] = 200
    temp_dict["ib"] = 0
    temp_dict["iw"] = False


    protocolType = dict['NetworkProtocolName']
    if protocolType == '' or  protocolType == 'http/1.1':
        protocolType = 'h1'
    else:
        protocolType = 'h2'

    if urlparse(temp_dict["ru"]).scheme == 'https':
        protocolType += 's'

    temp_dict["pt"] = protocolTypeDict()[protocolType]

    temp_dict["type"] = 'TimingData    '
    return temp_dict

def protocolTypeDict():
    return { "h1": "1",
             "h1s": "2",
             "h2": "3",
             "h2s": "4",
             "ws": "5",
             "wss": "6",
             "socket": "7"}

# dns解析，获取结果为(cnames, ip, port)
def dnsAnalysis(url):
    port = 80

    parse = urlparse(url)
    hostname = parse.hostname
    temp = 'nslookup ' + hostname
    lines = os.popen(temp)
    if ':' in parse.netloc:
        tempPort = parse.netloc.split(':')[1]
        port = int(tempPort)

    else:
        if parse.scheme == 'https':
            port = 443
    try:
        ip = gethostbyname(hostname)
    except:
        print('域名解析出错')

    array = []
    array.append(hostname)
    for line in lines.readlines():
        if 'canonical name' in line:
            content = line.split('canonical name = ')[1]
            content = content.replace('.\n', '')
            array.append(content)
    return  (array, ip, port)


def getCnames(url):
    hostname = urlparse(url).hostname
    temp = 'nslookup ' + hostname
    lines = os.popen(temp)

    array = []
    array.append(hostname)
    for line in lines.readlines():
        if 'canonical name' in line:
            content = line.split('canonical name = ')[1]
            content = content.replace('.\n', '')
            array.append(content)
    return array


# 提取WKNetAjaxData中的ru
def getRUFromWKNetAjaxData(dict):
    u = dict["u"]
    p = dict["p"]

    if len(p) <= 0 or len(u) <= 0:
        return ""
    if u.startswith('http'):
        return u

    url = urlparse(p)
    # print(url)
    # print(url.hostname)
    # print(url.netloc)
    # print(url.scheme)
    # print(url.path)

    if url:
        mainUrl = url.netloc
        pathUrlStr = u
        if pathUrlStr.startswith('/') or len(url.path) <= 0 or pathUrlStr.startswith('../'):
            requestMainStr = mainUrl
        else:
            requestMainStr = mainUrl + url.path

        if pathUrlStr.startswith('../'):
            pathUrlStr = '/' + pathUrlStr.split('../')[1]
        return url.scheme + '://' + requestMainStr + '/' + pathUrlStr

    return p

# 写入webview公有指标， type：0 Ajax，1 PD， 2 RD
def publicWebViewData(dict, type):
    temp_dict = {}
    if type == 0:
        temp_dict["ru"] = getRUFromWKNetAjaxData(dict)
        temp_dict["type"] = 'WKNetAjaxData '
    elif type == 1:
        temp_dict["ru"] = dict['url']
        temp_dict["type"] = 'PageData      '
    elif type == 2:
        temp_dict["ru"] = dict['name']
        temp_dict["type"] = 'ResultData    '

    dns = dnsAnalysis(temp_dict["ru"])
    temp_dict['cna'] = dns[0]
    if len(temp_dict['cna']) > 0:
        temp_dict['lc'] = temp_dict['cna'][-1]
    else:
        temp_dict['lc'] = ''
    temp_dict["tip"] = dns[1]
    temp_dict["tp"] = dns[2]

    protocolType = dict.get('pr')

    if protocolType:
        if protocolType == '' or protocolType == 'http/1.1':
            protocolType = 'h1'
        else:
            protocolType = 'h2'
    else:
        protocolType = 'h1'

    if urlparse(temp_dict["ru"]).scheme == 'https':
        protocolType += 's'
    temp_dict["pt"] = protocolTypeDict()[protocolType]

    temp_dict["li"] = 0
    temp_dict["lp"] = 0
    temp_dict["si"] = 0
    temp_dict["ib"] = 0
    temp_dict["rh"] = ''
    temp_dict["iw"] = True
    temp_dict["rhe"] = ''
    return  temp_dict

# 提取WKNetAjaxData中的数据指标
def extractionIndexWKNetAjaxData(dict):
    temp_dict = publicWebViewData(dict, 0)

    temp_dict["st"] = dict['fb']
    temp_dict["dt"] = differenceValue(dict['de'], dict['ds'])

    if dict['ssl']:
        temp_dict["sti"] = differenceValue(dict['ce'], dict['ssl'])
    else:
        temp_dict["sti"] = differenceValue(dict['ce'], 0)

    temp_dict["ct"] = differenceValue(dict['ce'], sum(dict['cs'], temp_dict['sti']))

    if dict['e'] == 0:
        temp_dict["rt"] = 999
    else:
        temp_dict["rt"] = dict['e'] * 1000


    temp_dict["rti"] = dict['fb'] * 1000
    if dict['st'] > 400:
        temp_dict["rti"] = 0
    elif temp_dict["rti"] == 0:
        temp_dict["rti"] = 999


    temp_dict["dti"] = dict['d']
    if temp_dict["dti"] == 0:
        temp_dict["dti"] = 999


    temp_dict["et"] = temp_dict["st"] + temp_dict["rt"]

    temp_dict["rd"] = dict['req']

    if dict['st'] > 400:
        temp_dict["rhe"] = dict['h']

    temp_dict["ei"] = dict['st']
    if dict['st'] == 200:
        temp_dict["ei"] = 0

    temp_dict["rds"] = dict['res']
    temp_dict["se"] = dict['st']

    try:
        for result in dict['h'].split('\n'):
            if result.startswith('content-type:'):
                temp_dict["mt"] = result.split('content-type: ')[1]
    except:
        print('mt AjaxData 获取失败')

    return temp_dict

# 提取PD中的数据指标
def extractionIndexPageData(dict):
    temp_dict = publicWebViewData(dict, 1)
    # print(dict)

    temp_dict["st"] = 0

    temp_dict["dt"] = differenceValue(dict['dle'], dict['dls']) / 1000

    if dict['scs']:
        temp_dict["sti"] = differenceValue(dict['ce'], dict['scs'])
    else:
        temp_dict["sti"] = 0
    temp_dict["sti"] /= 1000

    temp_dict["ct"] = differenceValue(dict['ce'] * 1000, sum(dict['cs'] * 1000, temp_dict['sti']), False)

    rt = differenceValue(dict['reqs'], dict['ce']) / 1000
    if rt == 0:
        temp_dict["rt"] = 999
    else:
        temp_dict["rt"] = rt

    rti = differenceValue(dict['rsps'], dict['reqs']) / 1000
    if rti == 0:
        temp_dict["rti"] = 999
    else:
        temp_dict["rti"] = rti

    dti = differenceValue(dict['rspe'], dict['rsps']) / 1000
    if dti == 0:
        temp_dict["dti"] = 999
    else:
        temp_dict["dti"] = dti

    temp_dict["et"] = temp_dict["st"] + temp_dict["rt"]
    temp_dict["rd"] = 0
    temp_dict["rds"] = 0
    temp_dict["ei"] = 0
    temp_dict["se"] = 200

    return temp_dict

# 提取RD中的数据指标
def extractionIndexResultData(dict):
    temp_dict = publicWebViewData(dict, 2)
    # print(dict)

    temp_dict["st"] = dict['st']

    temp_dict["dt"] = differenceValue(dict['dle'], dict['dls']) / 1000

    if dict['scs']:
        temp_dict["sti"] = differenceValue(dict['ce'], dict['scs'])
    else:
        temp_dict["sti"] = 0
    temp_dict["sti"] /= 1000

    temp_dict["ct"] = differenceValue(dict['ce'] * 1000, sum(dict['cs'] * 1000, temp_dict['sti']), False)

    rt = differenceValue(dict['reqs'], dict['ce']) / 1000
    if rt == 0:
        temp_dict["rt"] = 999
    else:
        temp_dict["rt"] = rt

    rti = differenceValue(dict['rsps'], dict['reqs']) / 1000
    if rti == 0:
        temp_dict["rti"] = 999
    else:
        temp_dict["rti"] = rti

    dti = differenceValue(dict['rspe'], dict['rsps']) / 1000

    if dti == 0:
        temp_dict["dti"] = rti
    else:
        temp_dict["dti"] = dti

    temp_dict["et"] = temp_dict["st"] + temp_dict["rt"]
    temp_dict["rd"] = 0
    temp_dict["rds"] = 0
    temp_dict["ei"] = 0
    temp_dict["se"] = 200

    return temp_dict

# 指标描述列表,添加描述即代表进行校验
def extractionIndexDesList():
    return [
        {"ru": "requestUrl请求地址"},
        {"si": ""},  # socketId tcp的socketid;（不用管)
        {"tp": "targetPort目标端口"},
        {"st": "startTimeUs请求起始时刻"},
        {"dt": "dnsTimeUs dns查询时间"},
        {"ct": "connectTimeUs tcp建连时间"},
        {"sti": "ssltimeUs"},
        {"rt": "requestTimeUs请求时间"},
        {"rti": "responseTimeUs响应时间"},
        {"dti": "downloadTimeUs下载用时"},
        {"et": "endTimeUs请求结束时刻"},  #
        {"rh": ""},  # requestHeader请求header
        {"rd": "requestDataSize请求数据大小"},
        {"rhe": "responseHeader响应header"},  #
        {"rds": "responseDataSize响应数据大小"},
        {"ei": "errorId错误ID"},
        {"se": "subErrorId子错误码"},  # subErrorId子错误码(B站需求：652原始错误码上报)
        {"ib": ""},  # isBackground是否后台发生
        {"mt": "mimetype"},
        {"rg": ""}, # requestGuid
        {"rgu": ""}, # responseGuid
        {"iw": "isWebview"},
        {"lc": "lastCname"},
        {"s": ""},  # signal信号量
        {"mi": ""}, # memberId会员ID
        {"kv": ""}, # kv键值对
        {"pt": "protocolType协议类型"},   #
        {"cna": "cname字符串数组"},
        {"tip": "targetIp：目标IP；"}, # 会上报IPV4或者IPV6；String(5.9新增) nslookup结果
        {"dsip": ""}, # dnsServerIp：手机localDNS；会上报IPV4或者IPV；String(5.9新增)
        {"ns": ""}, # networkStandard：网络制式；String；后台做2g 3g 4g的对应转换(5.9新增)
    ]

# 通过upload上传数据获取所有的网络数据
def getNetResults(uploadList):
    netResults = []
    for upload in uploadList:
        data = json.loads(upload)
        tempArray = data["udr"]["d"][0]["nr"]
        if len(tempArray) > 1:
            tempArray.pop(0)
            netResults += tempArray
    return netResults



# 处理log输出和upload网络上报数据顺序不一致问题，进行误差修正,以上报数据为基准,返回值为正确的顺序
def networkErrorCorrection(netResults, timingDatas, ajaxDatas, ajaxTimes, pageDatas):

    newTimingDatas = []
    tempTimingDatas = []

    for timingData in timingDatas:
        data = analysisTimingData(timingData)
        extractionIndexData = extractionIndexTimingData(data)
        tempTimingDatas.append(extractionIndexData)

    for ajaxData in ajaxDatas:
        tempAjaxData = extractionIndexWKNetAjaxData(json.loads(ajaxData))
        # 根据ajaxTime重新计算st 和 et
        tempAjaxData['st'] = ajaxTimes[tempAjaxData['ru']] - tempAjaxData['st'] * 1000
        tempAjaxData["et"] = tempAjaxData["st"] + tempAjaxData["rt"]
        tempTimingDatas.append(tempAjaxData)

    for pageData in pageDatas:
        tempData = json.loads(pageData)
        tempPageData = extractionIndexPageData(tempData['PD'])

        try:
            # 当前pageData的起始时间
            tempStartTime = 0
            if tempData['PD'].get("lee"):
                tempStartTime = tempData['PD']['lee']
            elif tempData['PD'].get('dc'):
                tempStartTime = tempData['PD']['dc']
            # 根据ajaxTime重新计算st 和 et
            tempPageData['st'] = ajaxTimes[tempPageData['ru']] - tempStartTime
            tempPageData["et"] = tempPageData["st"] + tempPageData["rt"]
        except:
            print('pageData st 和 et 计算有误')

        tempTimingDatas.append(tempPageData)

        for resultData in tempData['RD']:
            tempResultData = extractionIndexResultData(resultData)
            tempResultData['st'] = tempPageData['st'] + tempResultData['st']
            tempResultData["et"] = tempResultData["st"] + tempResultData["rt"]
            tempTimingDatas.append(tempResultData)

    for netResult in netResults:
        # 是否可以找到对应的数据
        isExit = False
        for timingData in tempTimingDatas:

           if netResult[0] == timingData.get("ru"):
                isExit = True
                newTimingDatas.append(timingData)
                tempTimingDatas.remove(timingData)
                break
        # 找不到匹配数据
        if isExit == False:
            newTimingDatas.append({})

    return newTimingDatas


# 整体数据比对
def allTimingDataSourceComparison(pageDatas, ajaxDatas, ajaxTimes, timingDatas, uploadList):
    netResults = getNetResults(uploadList)

    newTimingDatas = networkErrorCorrection(netResults, timingDatas, ajaxDatas, ajaxTimes, pageDatas)

    tip = "检测到待校验网络数据数量为" + str(len(netResults)) + "条"
    print(tip)

    i = 0
    for netResult in netResults:
        if len(newTimingDatas) <= i:
            break
        bval = singleTimingDataComparison(newTimingDatas[i], netResult)
        i += 1


# 判断是否为浮点数
def isFloat(value):
    try:
        x = float(value)  # 此处更改想判断的类型
    except TypeError:
        return False
    except ValueError:
        return False
    except Exception as e:
        return False
    else:
        return True


# 具体的数据校验是否符合
def dataVerification(value1, value2):

    if type(value1) is list:
        if value1 == value2:
            return True
    value1 = str(value1).lower().strip()
    value2 = str(value2).lower().strip()
    if value1 == value2:
        # if len(value1) == 0:
        #     return False
        return True
    if isFloat(value1) and isFloat(value2):
        f1 = float(value1)
        f2 = float(value2)

        if abs(f1 - f2) <= 1:
            return True
    return False

# 单条网络数据的比对
def singleTimingDataComparison(timingData, netResult):

    print("---------网络数据校验开始-------------")

    if len(netResult) != 31:
        print("upload中网络数据数量有误")
        return False

    if len(timingData) <= 0:
        print("校验失败❌❌❌, 未检测到对应的网络数据")
        print(netResult)
        print("---------网络数据校验结束-------------\n\n")
        return False

    isPass = True
    i = 0
    for desDic in extractionIndexDesList():
        # 每个字典只会存在一个，key-value
        for key, value in desDic.items():
            # result = key + "==>>>" + "\n" + " upload中的数据为:" + str(netResult[i]) + "\n timingData中的数据为:" + str(
            #     timingData.get(key)) + "(" + value + ")"
            # 如果没有具体的描述则不进行比对
            if len(value) > 0:
                result = value + "(" + key + ")" + "  ==>>  "
                bval = dataVerification(netResult[i], timingData.get(key))
                if bval == False:
                    isPass = False
                    result += "校验失败❌❌❌"
                else:
                    result += "校验通过✅✅✅"

                result += "\nupload        : " + str(netResult[i])
                result += "\n" + str(timingData['type']) + ': ' + str(timingData.get(key))
                print(result)
        i += 1
    print("---------网络数据校验结束-------------\n\n")
    return isPass

def getAjaxTime(string):
    ajaxTime = string.split("Time] ")[1]
    url = ajaxTime.split(" ")[0]
    time = ajaxTime.split(" ")[1]
    return {url.split(":", 1)[1]: int(time.split(":")[1].rstrip())}

def fileParsing(path):
    f = open(path, "r", encoding='UTF-8')
    upload_list = []
    upload_str = ""
    isStart = 0

    content_list = []
    temp_list = []

    ajaxDatas = []
    pageDatas = []
    ajaxTimes = {}
    for line in f:

        if '[TimingData]' in line:
            temp_list.append(line.strip())
            if '-结束-' in line:
                content_list.append(temp_list.copy())
                temp_list.clear()

        if isStart == 1:
            upload_str += line
            if '}\n' == line:
                isStart = 0
                # 过滤upload的响应结果
                if len(upload_str) > 100:
                    upload_list.append(upload_str)
                upload_str = ""

        # 捕获upload 上传数据的起始位置
        if '[UPLOAD]' in line:
            if len(line.split("[UPLOAD]")[1]) <= 3:
                isStart = 1

        # print(line)
        if 'NetAjaxData>: ' in line:
            ajaxDatas.append(line.split("NetAjaxData>: ")[1])
        if 'NetPageData>: ' in line:
            pageDatas.append(line.split("PageData>: ")[1])

        # 提取时间
        if '[AjaxTime]' in line or '[PageDataTime]' in line:
            ajaxTimes.update(getAjaxTime(line))

    allTimingDataSourceComparison(pageDatas, ajaxDatas, ajaxTimes, content_list, upload_list)

    f.close()


filePath = "2.txt"
if len(sys.argv) > 1:
    filePath = sys.argv[1]
print("待解析文件:" + filePath)
fileParsing(filePath)