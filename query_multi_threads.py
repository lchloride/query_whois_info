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

MAX_LENGTH = 100
RESULT_SET_DOMAIN_COL = 0
RESULT_SET_ISFINISHED_COL = 1
RESULT_SET_DETAILS_COL = 2
SCREEN = 0x1
FILE_OUT = 0x2
FILE_ERR = 0x4
MAX_TRY_TIMES = 3
WAIT_TIME = 10
download_threads = []
file_handler = {"in": None, "out": None, "err": None}
thread_count = 0
read_count = 0
logger = None
server_stat = {}
server_ips = {}


# 获取whois信息的函数，调用pywhois库的改进版本；获取的信息为json格式Unicode字符串
def query_whois(domain_set, result_list):
    try:
        w = whois.whois(domain_set["domain"])
    except socket.error, arg:
        err_str = str(arg[0]).replace('\n', '')
        result_list.put((domain_set, False, "SocketError: %s at server [%s]" % (err_str, arg[1])))
        logger.write_log("SocketError: %s with [%s] at server [%s]"
                         % (err_str, domain_set["domain"], arg[1]), SCREEN | FILE_ERR)
    except PywhoisError, arg:
        err_str = str(arg).replace('\n', '')[:20]
        result_list.put((domain_set, False, "PywhoisError:" + err_str))
        logger.write_log("PywhoisError: %s with %s" % (err_str, domain_set["domain"]), SCREEN | FILE_ERR)
    except AttributeError, arg:
        err_str = str(arg).replace('\n', '')
        result_list.put((domain_set, False, "AttributeError:" + err_str))
        logger.write_log("AttributeError: %s with [%s]" % (err_str, domain_set["domain"]), SCREEN | FILE_ERR)
    else:
        result_list.put((domain_set, True, w))


def read_domain_to_ready(queue):
    global read_count
    try:
        if read_count <= 600000:
            domain = file_handler["in"].readline()
            if not domain:
                return False
        else:
            return False
    except IOError, args:
        return False
    else:
        read_count += 1
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
    logger.write_log("Domain [" + domain_set["domain"] + "] has been tried " + str(MAX_TRY_TIMES)
                     + (" times with error message: %s" % domain_set["error_msg"]), SCREEN | FILE_ERR)


# 分配线程，用来创建一个获取whois信息的下载线程
def allocate(ready_queue, running_queue, waiting_queue, result_list):
    while len(running_queue) + len(waiting_queue) + ready_queue.qsize() > 0:
        # while not allocate_exit_signal:
        # print "running: %d, waiting: %d, ready: %d" % (len(running_queue), len(waiting_queue), ready_queue.qsize())
        logger.write_log(("running: %d, waiting: %d, ready: %d"
                          % (len(running_queue), len(waiting_queue), ready_queue.qsize())), SCREEN)

        global thread_count
        thread_count += 1
        if thread_count % 500 == 0:
            time.sleep(2)
            if thread_count % 1000 == 0 and len(running_queue) > MAX_LENGTH / 2:
                time.sleep(5)
        else:
            time.sleep(0.01)
        domain = ready2running(ready_queue, running_queue)
        if domain["domain"] == "localhost":
            break
        thread = BaseThread.BaseThread(query_whois, (domain, result_list), 'Thread-' +
                                       repr(thread_count))
        thread.start()
        download_threads.append(thread)


def handle_result(ready_queue, running_queue, waiting_queue, result_list):
    while ready_queue.qsize() + len(running_queue) + len(waiting_queue) > 0:
        result_set = result_list.get()
        remove_from_running(running_queue, result_set[RESULT_SET_DOMAIN_COL])
        if result_set[RESULT_SET_ISFINISHED_COL]:  # 获取whois信息成功
            hostname = result_set[RESULT_SET_DETAILS_COL][1]
            if hostname in server_stat:
                server_stat[hostname] += 1
            else:
                server_stat[hostname] = 1
            read_domain_to_ready(ready_queue)

            '''print "Query whois information of domain [=%s] succeed." \
                  % result_set[RESULT_SET_DOMAIN_COL]["domain"]
            file_handler["out"].write(
                "Query whois information of domain [=%s] succeed."
                % result_set[RESULT_SET_DOMAIN_COL]["domain"])'''
            logger.write_log("Query whois information of domain [" +
                             result_set[RESULT_SET_DOMAIN_COL]["domain"] + "] succeed at server ["+
                             result_set[RESULT_SET_DETAILS_COL][1]+"].",
                             SCREEN | FILE_OUT)
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
    logger = Log(MAX_LENGTH * 10, out_file_handler_list)

    st_time = time.time()

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

    logger.write_log("%s: Duration:%s total rows:%s (threads:%s)"
                     % ('Main end', time.time()-st_time, read_count, thread_count), SCREEN)
    logger.write_log("Server Distribution:", SCREEN)
    for key in server_stat.keys():
        logger.write_log("%s - %d" % (key, server_stat[key]), SCREEN)

    file_handler["in"].close()
    file_handler["out"].close()
    file_handler["err"].close()
    logger.write_log("Exiting Main Thread", SCREEN)

    logger.kill()
    logger.get_thread().join()


if __name__ == '__main__':
    main()
