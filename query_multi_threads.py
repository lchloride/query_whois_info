#!/usr/bin/python
# -*- coding: UTF-8 -*-

import threading
import time
from Queue import Queue

import socket
import BaseThread
import sys
import whois
from whois.parser import PywhoisError
from log import Log

# 使用utf-8编码
reload(sys)
sys.setdefaultencoding('utf8')

MAX_LENGTH = 10
RESULT_SET_DOMAIN_COL = 0
RESULT_SET_ISFINISHED_COL = 1
RESULT_SET_DETAILS_COL = 2
SCREEN = 0x1
FILE_OUT = 0x2
FILE_ERR = 0x4
MAX_TRY_TIMES = 3
WAIT_TIME = 5
download_threads = []
file_handler = {"in": None, "out": None, "err": None}
count = 0
#allocate_exit_signal = False
#string_pool = Queue(10 * MAX_LENGTH)

logger = None

"""
# 完成一条内容的输出，输出内容不保证即刻执行
# flag表示待输出的设备，0为退出线程，1为输出到屏幕
def write_log(content, flag):
    string_set = {"flag": flag, "content": content}
    string_pool.put(string_set)


# 向屏幕/文件输出信息的线程体
def display_log():
    while True:
        string_set = string_pool.get()
        if string_set["flag"] == 0:
            break
        else:
            if string_set["flag"] & 0x1 == 0x1:
                print string_set["content"]
            if string_set["flag"] & 0x4 == 0x4:
                file_handler["out"].write(string_set["content"])
            if string_set["flag"] & 0x8 == 0x8:
                file_handler["err"].write(string_set["content"])"""


# 获取whois信息的函数，调用pywhois库的改进版本；获取的信息为json格式Unicode字符串
def query_whois(domain_set, result_list):
    try:
        w = whois.whois(domain_set["domain"])
    except socket.error, arg:
        err_str = str(arg).replace('\n', '')
        result_list.put((domain_set, False, "SocketError:"+err_str))
        logger.write_log("SocketError: %s with [%s]" %(err_str, domain_set["domain"]), SCREEN|FILE_ERR)
    except PywhoisError, arg:
        err_str = str(arg).replace('\n', '')[:20]
        result_list.put((domain_set, False, "PywhoisError:"+err_str))
        logger.write_log("PywhoisError: %s with %s" %(err_str, domain_set["domain"]), SCREEN|FILE_ERR)
    else:
        result_list.put((domain_set, True, w))


def read_domain_to_ready(queue):
    try:
        if count <= 50:
            domain = file_handler["in"].readline()
            if not domain:
                return False
        else:
            return False
    except IOError, args:
        return False
    else:
        item = {"domain": domain[:-1], "try_times": 0, "server": None,
                "error_msg": [], "is_error": False}
        queue.put(item)
        return True


# 从ready队列中取出一个域名放入running队列中
def ready2running(ready_queue, running_queue):
    domain = ready_queue.get()
    running_queue.append(domain)
    return domain


# 从running队列中删除值为domain_set的元素
def remove_from_running(running_queue, domain_set):
    running_queue.remove(domain_set)


def waiting2ready(waiting_queue, ready_queue, domain_set):
    waiting_queue.remove(domain_set)
    ready_queue.put(domain_set)


def report_error(domain_set):
    logger.write_log("Domain ["+domain_set["domain"]+"] has been tried "+ str(MAX_TRY_TIMES)
              +(" times with error message: %s" % domain_set["error_msg"]), SCREEN|FILE_ERR)


# 分配线程，用来创建一个获取whois信息的下载线程
def allocate(ready_queue, running_queue, waiting_queue, result_list):
    while len(running_queue) + len(waiting_queue) + ready_queue.qsize() > 0:
        # while not allocate_exit_signal:
        # print "running: %d, waiting: %d, ready: %d" % (len(running_queue), len(waiting_queue), ready_queue.qsize())
        logger.write_log(("running: %d, waiting: %d, ready: %d"
                   % (len(running_queue), len(waiting_queue), ready_queue.qsize())), SCREEN)

        global count
        count = count + 1
        domain = ready2running(ready_queue, running_queue)
        if domain["domain"] == "localhost":
            break
        thread = BaseThread.BaseThread(query_whois, (domain, result_list), 'Thread-' + repr(count))
        thread.start()
        download_threads.append(thread)


def handle_result(ready_queue, running_queue, waiting_queue, result_list):
    while ready_queue.qsize() + len(running_queue) + len(waiting_queue) > 0:
        result_set = result_list.get()
        remove_from_running(running_queue, result_set[RESULT_SET_DOMAIN_COL])
        if result_set[RESULT_SET_ISFINISHED_COL]:  # 获取whois信息成功
            read_domain_to_ready(ready_queue)

            '''print "Query whois information of domain [=%s] succeed." \
                  % result_set[RESULT_SET_DOMAIN_COL]["domain"]
            file_handler["out"].write(
                "Query whois information of domain [=%s] succeed."
                % result_set[RESULT_SET_DOMAIN_COL]["domain"])'''
            logger.write_log("Query whois information of domain ["+
                      result_set[RESULT_SET_DOMAIN_COL]["domain"]+"] succeed.",
                      SCREEN|FILE_OUT)
        else:
            domain_set = result_set[RESULT_SET_DOMAIN_COL]
            domain_set["try_times"] += 1
            domain_set["error_msg"].append(result_set[RESULT_SET_DETAILS_COL])
            if domain_set["try_times"] >= MAX_TRY_TIMES:
                report_error(domain_set)
                read_domain_to_ready(ready_queue)
            else:
                waiting_queue.append(domain_set)
                thread = threading.Timer(WAIT_TIME,
                                         waiting2ready,
                                         (waiting_queue, ready_queue, domain_set))
                thread.start()


def main():
    file_handler["in"] = open("fin.txt", "r")
    file_handler["out"] = open("fout.txt", "w")
    file_handler["err"] = open("ferr.txt", "w")

    ready_queue = Queue(MAX_LENGTH)
    running_queue = []
    waiting_queue = []
    result_list = Queue(MAX_LENGTH)

    # 读取一部分域名进入queue list
    for i in range(MAX_LENGTH):
        if not read_domain_to_ready(ready_queue):
            print "Cannot Initialize Ready Queue."
            return

    # 创建日志输出线程
    global logger
    out_file_handler_list = [file_handler["out"], file_handler["err"]]
    logger = Log(MAX_LENGTH*10, out_file_handler_list)

    # 创建分发线程
    allocate_thread = BaseThread.BaseThread(allocate,
                                            (ready_queue, running_queue, waiting_queue, result_list),
                                            'allocate')
    allocate_thread.start()
    # download_threads.append(allocate_thread)

    # 创建结果处理线程
    handle_result_thread = BaseThread.BaseThread(handle_result,
                                                 (ready_queue, running_queue, waiting_queue, result_list),
                                                 'handle_result')
    handle_result_thread.start()
    download_threads.append(handle_result_thread)

    # 等待所有线程完成
    for t in download_threads:
        t.join()

    item = {"domain": "localhost", "try_times": 0, "server": None, "error_msg": [], "is_error": False}
    ready_queue.put(item)

    logger.write_log("%s: %s total rows:%s" % ('Main end', time.ctime(time.time()), count), SCREEN)
    file_handler["in"].close()
    file_handler["out"].close()
    file_handler["err"].close()
    logger.write_log("Exiting Main Thread", SCREEN)

    logger.kill()
    logger.get_thread().join()

if __name__ == '__main__':
    main()
