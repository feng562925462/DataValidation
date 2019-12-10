# coding=utf-8

import sys


def fileParsing(path):
    f = open("2.txt","r", encoding='UTF-8')
    upload_list = []
    upload_str = ""
    isStart = False

    content_list = []
    temp_list = []
    for line in f:
        if isStart == True:
            print(line)
            if '}\n' == line:
                isStart = False
        # 捕获upload 上传数据的起始位置
        if '[CONFIG]' in line:
            if len(line.split("[CONFIG]")[1]) <= 3:
                isStart = True

    f.close()




fileParsing("1")
