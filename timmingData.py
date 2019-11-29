# coding=utf-8

import sys
import json
from decimal import Decimal as D

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
    "url":"0",
    "time":"0",
    "ResponseBodyBytesDecoded":"0",
    "TotalBytesReceived":"0",
    "LocalAddressAndPort":"0",
    "RemoteAddressAndPort":"0",
    "RequestHeaderSize":"0",
    "SecureConnectionStart":"0",
    "ResponseHeaderSize":"0",
    "TimingDataInit":"0",
    "NetworkProtocolName":"0",
    "ConnectionInterfaceIdentifier":"0",
    "ResponseStart":"0",
    "ResponseBodyBytesReceived":"0",
    "ConnectionUUID":"0",
    "DomainLookupStart":"0",
    "FetchStart":"0",
    "DomainLookupEnd":"0",
    "RequestEnd":"0",
    "ConnectionReused":"0",
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
def differenceValue(f1, f2, isChange = True):
    result = D(f1) - D(f2)
    if isChange == True:
        result *= 1000000
    return round(result, 1)

# 和计算
def sum(f1, f2, isChange = False):
    result = D(f1) + D(f2)
    if isChange == True:
        result *= 1000000
    return round(result, 1)

# 提取TimingData中的数据指标
def extractionIndexTimingData(dict):
    temp_dict = {}
    temp_dict["ru"] = dict.get("url")
    temp_dict["tp"] = dict.get("RemoteAddressAndPort").split(":")[1]
    temp_dict["st"] = differenceValue(dict.get("time"), differenceValue(dict.get("ResponseEnd"), dict.get("FetchStart")), False)

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
    temp_dict["et"] = 0
    temp_dict["rh"] = 0
    temp_dict["rd"] = sum(dict.get("TotalBytesSent"), dict.get("RequestHeaderSize"))
    temp_dict["rhe"] = 0
    temp_dict["rds"] = sum(dict.get("TotalBytesReceived"), dict.get("ResponseHeaderSize"))
    temp_dict["ei"] = 0
    temp_dict["se"] = 0
    temp_dict["ib"] = 0
    temp_dict["tip"] = dict.get("RemoteAddressAndPort").split(":")[0]
    return temp_dict

# 指标描述列表,添加描述即代表进行校验
def extractionIndexDesList():
    return [
        {"ru": "requestUrl请求地址"},
        {"si": ""}, # socketId tcp的socketid;（不用管)
        {"tp": "targetPort目标端口"},
        {"st": "startTimeUs请求起始时刻"},
        {"dt": "dnsTimeUs dns查询时间"},
        {"ct": "connectTimeUs tcp建连时间"},
        {"sti": "ssltimeUs"},
        {"rt": "requestTimeUs请求时间"},
        {"rti": "responseTimeUs响应时间"},
        {"dti": "downloadTimeUs下载用时"},
        {"et": ""}, # endTimeUs请求结束时刻
        {"rh": ""}, # requestHeader请求header
        {"rd": "requestDataSize请求数据大小"},
        {"rhe": ""}, # responseHeader响应header
        {"rds": "responseDataSize响应数据大小"},
        {"ei": ""}, # errorId错误ID
        {"se": ""}, # subErrorId子错误码(B站需求：652原始错误码上报)
        {"ib": ""}, # isBackground是否后台发生
        {"mt": ""},
        {"rg": ""},
        {"rgu": ""},
        {"iw": ""},
        {"lc": ""},
        {"s": ""},
        {"mi": ""},
        {"kv": ""},
        {"pt": ""},
        {"cna": ""},
        {"tip": "targetIp：目标IP；会上报IPV4或者IPV6；String(5.9新增)"},
        {"dsip": ""},
        {"ns": ""},
        ]

# 输出解析的指标
def printExtractionIndex(dict):

    desArray = extractionIndexDesList()

    for desDic in desArray:
        for key, value in desDic.items():
            result = key + ":" + str(dict.get(key)) + "(" + value + ")"
            print(result)


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

# 处理log输出和upload网络上报数据顺序不一致问题，进行误差修正,以上报数据为基准,返回值为正确的timingDatas顺序
def networkErrorCorrection(netResults, timingDatas):
    newTimingDatas = []
    tempTimingDatas = []

    for timingData in timingDatas:
        data = analysisTimingData(timingData)
        extractionIndexData = extractionIndexTimingData(data)
        tempTimingDatas.append(extractionIndexData)

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
def allTimingDataSourceComparison(timingDatas, uploadList):
    netResults = getNetResults(uploadList)

    newTimingDatas = networkErrorCorrection(netResults, timingDatas)

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
        x = float(value) #此处更改想判断的类型
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
    if value1 == value2:
        if len(value1) == 0:
            return False
        return True
    if isFloat(value1) and isFloat(value2):
        f1 = float(value1)
        f2 = float(value2)

        if abs(f1 - f2) <= 1:
            return True
    return False

# 单条网络数据的比对
def singleTimingDataComparison(timingData, netResult):
    print("---------timingData数据校验开始-------------")

    if len(netResult) != 31:
        print("upload中网络数据数量有误")
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
                bval =  dataVerification(netResult[i], str(timingData.get(key)))
                if bval == False:
                    isPass = False
                    result += "校验失败❌❌❌"
                else:
                    result += "校验通过✅✅✅"

                result += "\nupload     : " + str(netResult[i])
                result += "\ntimingData : " + str(timingData.get(key))
                print(result)
        i += 1
    print("---------timingData数据校验结束-------------")
    return isPass

def fileParsing(path):
    f = open(path,"r", encoding='UTF-8')
    upload_list = []
    upload_str = ""
    isStart = 0

    content_list = []
    temp_list = []
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

    allTimingDataSourceComparison(content_list, upload_list)
    f.close()

filePath = "1.txt"
if len(sys.argv) > 1:
    filePath = sys.argv[1]
print("待解析文件:" + filePath)
fileParsing(filePath)