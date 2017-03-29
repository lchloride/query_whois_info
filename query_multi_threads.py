#!/usr/bin/python
# -*- coding: UTF-8 -*-

import threading
import time
import whois
import socket

import sys

reload(sys)
sys.setdefaultencoding('utf8')


class MyThread(threading.Thread):
    def __init__(self, threadID, name, ip, fo, ferr):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.ip = ip
        self.fo = fo
        self.ferr = ferr;
        self.count = threadID

    def run(self):
        # print "Starting " + self.name
        print_time(self.name, self.ip, self.count)
        # 获得锁，成功获得锁定后返回True
        # 可选的timeout参数不填时将一直阻塞直到获得锁定
        # 否则超时后将返回False
        # threadLock.acquire()
        # print_time(self.name, self.counter, 3)
        # 释放锁
        # threadLock.release()


def print_time(threadName, ip, count):
    try:
        w = whois.whois(ip)
    except socket.error, arg:
        (errno, err_msg) = arg
        print "error with " + threadName + ", " + ip + " errMsg: " + err_msg + ", [" + errno + "]"
        ferr.write("error with: %s -%s. Msg: %s, [%s]" % (threadName, ip, err_msg, errno))
    else:
        print "%s: %s %s" % (threadName, time.ctime(time.time()), ip)
        fo.write("%s: %s\n" % (threadName, time.ctime(time.time())))
        fo.write("%s - %s\n" % (ip, w.text))
        fo.write("--------------------\n")


threadLock = threading.Lock()
threads = []
ip_list = ['google.com', 'baidu.com', 'jd.com', 'facebook.com', 'twitter.com', 'bilibili.tv', 'qq.com', 'a.com',
           'taobao.com', 'bh3.com', 'github.com', 'abc.com']
# 创建新线程
# thread1 = myThread(1, "Thread-1", 1)
# thread2 = myThread(2, "Thread-2", 2)

# 开启新线程
# thread1.start()
# thread2.start()

# 添加线程到线程列表
# threads.append(thread1)
# threads.append(thread2)

count = 0
times = 1
fo = open("foo.txt", "w")
fi = open("fin.txt", "r")
ferr = open("ferr.txt", "w")
print "%s: %s" % ('Main start', time.ctime(time.time()))
for index in range(times):
    # for ip_item in ip_list:
    while 1:
        lines = fi.readlines(10000)
        if not lines:
            break
        for ip_item in lines:
            count += 1
            thread = MyThread(count, "Thread-" + str(count), ip_item[0:len(ip_item) - 1], fo, ferr)
            thread.start()
            threads.append(thread)
            if count % 500 == 0:
                # time.sleep(1)
                exit_flag = True
                break
        if exit_flag:
            break

# 等待所有线程完成
for t in threads:
    t.join()
print "%s: %s total rows:%s" % ('Main end', time.ctime(time.time()), count)
fi.close()
fo.close()
ferr.close()
print "Exiting Main Thread"
