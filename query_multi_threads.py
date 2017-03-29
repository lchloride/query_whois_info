#!/usr/bin/python
# -*- coding: UTF-8 -*-

import threading
import time
from Queue import Queue

import whois
from whois.parser import PywhoisError
import socket
import BaseThread
import sys

# 使用utf-8编码
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
        print_time(self.name, self.ip, self.count, self.fo, self.ferr)
        # 获得锁，成功获得锁定后返回True
        # 可选的timeout参数不填时将一直阻塞直到获得锁定
        # 否则超时后将返回False
        # threadLock.acquire()
        # print_time(self.name, self.counter, 3)
        # 释放锁
        # threadLock.release()


def print_time(threadName, ip, count, fo, ferr):
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


# 获取whois信息的函数，调用pywhois库的改进版本；获取的信息为json格式Unicode字符串
def query_whois(domain_set, result_list):
    try:
        w = whois.whois(domain_set["domain"])
    except socket.error, arg:
        (errno, err_msg) = arg
        print "error with " + ", " + domain_set["domain"] + " errMsg: " + err_msg + ", [" + errno + "]"
    except PywhoisError, arg:
        print "PywhoisError: " + arg
    else:
        result_list.put((domain_set, True, w))


threadLock = threading.Lock()
threads = []
ip_list = ['google.com', 'baidu.com', 'jd.com', 'facebook.com', 'twitter.com', 'bilibili.tv', 'qq.com', 'a.com',
           'taobao.com', 'bh3.com', 'github.com', 'abc.com']


def do():
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


MAX_LENGTH = 10
RESULT_SET_DOMAIN_COL = 0
RESULT_SET_ISFINISHED_COL = 1
RESULT_SET_DETAILS_COL = 2
download_threads = []
global count
count = 0


def read_domain_to_ready(queue, fin):
    domain = fin.readlines(1)
    item = {"domain": domain, "try_times": 0, "server": None, "is_error": False}
    queue.put(item)


# 从ready队列中取出一个域名放入running队列中
def ready2running(ready_queue, running_queue):
    domain = ready_queue.get();
    running_queue.append(domain);
    return domain

# 从running队列中删除值为domain_set的元素
def remove_from_running(running_queue, domain_set):
    running_queue.remove(domain_set)


# 分配线程，用来创建一个获取whois信息的下载线程
def allocate(ready_queue, running_queue, waiting_queue, result_list):
    while len(running_queue) + len(waiting_queue) + len(ready_queue) > 0:
        global count
        count = count + 1;
        domain = ready2running(ready_queue, running_queue)
        download_threads.append(BaseThread(query_whois, (domain, result_list), \
                                           'Thread-' + count))


def handle_result(ready_queue, running_queue, waiting_queue, result_list):
    while len(ready_queue) + len(running_queue) + len(waiting_queue) == 0:
        result_set = result_list.get()
        remove_from_running(result_set[RESULT_SET_DOMAIN_COL])
        if result_set[RESULT_SET_ISFINISHED_COL]:  # 获取whois信息成功



def main():
    fin = open("fin.txt", "r")
    ready_queue = Queue(MAX_LENGTH)
    running_queue = []
    waiting_queue = Queue(MAX_LENGTH)
    result_list = Queue(MAX_LENGTH)

    # 读取一部分域名进入queue list
    for i in range(MAX_LENGTH):
        read_domain_to_ready(ready_queue, fin)

    # 创建分发线程
    allocate_thread = BaseThread(allocate, \
                                 (ready_queue, running_queue, waiting_queue, result_list), \
                                 'allocate')

    #
    handle_result_thread = BaseThread()


if __name__ == '__main__':
    do()
