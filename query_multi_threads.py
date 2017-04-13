#!/usr/bin/python
# -*- coding: UTF-8 -*-

import threading
import time
from Queue import Queue
import traceback

import socket

import datetime
import random
import BaseThread
import sys
import whois
from whois.parser import PywhoisError
from log import Log
from threadpool import WorkRequest, WorkerThread, ThreadPool, NoResultsPending

# 使用utf-8编码
reload(sys)
sys.setdefaultencoding('utf8')

MAX_LENGTH = 70
RESULT_SET_DOMAIN_COL = 0
RESULT_SET_ISFINISHED_COL = 1
RESULT_SET_DETAILS_COL = 2
SCREEN = 0x1
FILE_OUT = 0x2
FILE_ERR = 0x4
FILE_RETRY = 0x8
FILE_IN_SERVER = 0x10
FILE_WHOIS_ERR = 0x20
FILE_RESULT = 0x40
MAX_TRY_TIMES = 3
WAIT_TIME = 10
# download_threads = []
thread_pool = ThreadPool(MAX_LENGTH)
file_handler = {"in": None, "out": None, "err": None, "retry": None, "in_server": None,
                "whois_err": None, "result": None}
thread_count = 0
read_count = 0
logger = None
server_stat = {}
server_ips = {}
read_buffer = []
server_list = []
proxy_list = [{"ip": "localhost", "port": 1080},
              {"ip": "120.24.245.193", "port": 1080},
              {"ip": "27.152.181.217", "port": 8080},
              {"ip": "202.38.95.66", "port": 1080}]


def random_proxy():
    l = len(proxy_list)
    idx = random.randint(0, l-1)
    return proxy_list[idx]


# 获取whois信息的函数，调用pywhois库的改进版本；获取的信息为json格式Unicode字符串
def query_whois(domain_set, result_list, **kwds):
    try:
        if domain_set["try_times"] == 0:
            w = whois.whois(domain_set["domain"], domain_set["server"], random_proxy())
        else:
            w = whois.whois(domain_set["domain"], None, random_proxy())
    except socket.error, arg:
        err_str = str(arg[0]).replace('\n', '')
        result_list.put((domain_set, False, "SocketError: %s at server [%s] times:%d"
                         % (err_str, arg[1], domain_set["try_times"])))
        logger.write_log("SocketError: %s with [%s] at server [%s] times:%d"
                         % (err_str, domain_set["domain"], arg[1], domain_set["try_times"]),
                         SCREEN | FILE_ERR)
        return False
    except PywhoisError, arg:
        err_str = str(arg).replace('\n', '')
        result_list.put((domain_set, False, "PywhoisError:" + err_str))
        logger.write_log("PywhoisError: %s with %s" % (err_str[:20], domain_set["domain"]),
                         SCREEN | FILE_ERR)
        if err_str.find('No match for') == -1 and \
                        err_str.find('Not found') == -1 and \
                        err_str.find('not found') == -1 and \
                        err_str.find('NOT FOUND') == -1 and \
                        err_str.find('No entries found') == -1 and \
                        err_str.find('No match') == -1 and \
                        err_str.find('No Data Found') == -1:
            logger.write_log("PywhoisError: %s with %s" % (err_str, domain_set["domain"]),
                             FILE_WHOIS_ERR)
        return False
    except AttributeError, arg:
        err_str = str(arg).replace('\n', '')
        result_list.put((domain_set, False, "AttributeError:" + err_str))
        logger.write_log("AttributeError: %s with [%s]"
                         % (err_str, domain_set["domain"]), SCREEN | FILE_ERR)
        return False
        # logger.write_log("AttributeError: %s with [%s]. Trace:%s"
        #               % (err_str, domain_set["domain"], traceback.print_stack()), SCREEN|FILE_ERR)
    else:
        if w is not None:
            result_list.put((domain_set, True, w))
            return True
        else:
            result_list.put((domain_set, False, "Result is None."))
            return False


def gene_serverip_buffer():
    logger.write_log("Start to generate IP buffer of whois server.", SCREEN)
    for server in server_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, 43))
            server_ips[server] = s.getpeername()[0]
            s.close()
        except socket.error as s:
            logger.write_log("Cannot obtain whois server IP since %s" % s, SCREEN)


def read_domain():
    logger.write_log("Start to read domains.", SCREEN)
    domain_server_list = []
    try:
        fin_server = open("fin_server.txt", "r")
    except IOError:
        domain_list = file_handler["in"].readlines()
        for domain in domain_list:
            domain_server_list.append({"domain": domain[:-1], "server": None})
        server_list = ["localhost"]
    else:
        classification = {}
        for line in fin_server:
            domain, server = line[:-1].split(" / ")
            if server.find(".") == -1:
                server = "localhost"
            if server not in classification.keys():
                classification[server] = []
            classification[server].append(domain)
        for server in classification.keys():
            for domain in classification[server]:
                domain_server_list.append({"domain": domain, "server": server})
        server_list = classification.keys()

    l = len(domain_server_list) / MAX_LENGTH
    for i in range(MAX_LENGTH):
        read_buffer.append([])
    for i in range(MAX_LENGTH):
        for j in range(l):
            read_buffer[i].append(domain_server_list[i*l+j])
    remain = len(domain_server_list) % MAX_LENGTH

    for i in range(remain):
        read_buffer[i].append(domain_server_list[l*MAX_LENGTH+i])


def read_domain_to_ready(queue):
    global read_count, read_buffer
    try:
        if read_count <= 500:
            idx = read_count % MAX_LENGTH
            if len(read_buffer[idx]) == 0:
                return False
            domain = read_buffer[idx][0]["domain"]
            server = read_buffer[idx][0]["server"]
            del read_buffer[idx][0]
            if not domain:
                return False
        else:
            return False
    except IOError, args:
        return False
    except IndexError, args:
        logger.write_log("index: %s, length: %s" % (read_count, len(read_buffer)), SCREEN)
        return False
    else:
        read_count += 1
        item = {"domain": domain, "try_times": 0, "server": server,
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
    flag = False
    for s in domain_set["error_msg"]:
        if s.find("PywhoisError") != -1:
            flag = True
            break

    if flag:
        logger.write_log("Domain [" + domain_set["domain"] + "] has been tried " + str(MAX_TRY_TIMES)
                         + (" times with error message: %s" % domain_set["error_msg"]),
                         SCREEN | FILE_WHOIS_ERR)
    else:
        logger.write_log("Domain [" + domain_set["domain"] + "] has been tried " + str(MAX_TRY_TIMES)
                         + (" times with error message: %s" % domain_set["error_msg"]),
                         SCREEN | FILE_ERR)
    logger.write_log("%s" % domain_set["domain"], FILE_RETRY)


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
        '''thread = BaseThread.BaseThread(query_whois, (domain, result_list), 'Thread-' +
                                       repr(thread_count))
        thread.start()
        download_threads.append(thread)'''
        req = WorkRequest(query_whois, args=(domain, result_list),
                          kwds={"threadname": 'Thread-' + repr(thread_count)})
        thread_pool.putRequest(req)
        strptime = datetime.datetime.strptime
        thread_pool.poll()
    thread_pool.stop()


def handle_result(ready_queue, running_queue, waiting_queue, result_list):
    while ready_queue.qsize() + len(running_queue) + len(waiting_queue) > 0:
        result_set = result_list.get()
        remove_from_running(running_queue, result_set[RESULT_SET_DOMAIN_COL])
        if result_set[RESULT_SET_ISFINISHED_COL]:  # 获取whois信息成功
            try:
                hostname = result_set[RESULT_SET_DETAILS_COL][1]
            except TypeError, arg:
                logger.write_log("[%s]result_set: %s" % (arg, result_set), SCREEN)
            if hostname in server_stat:
                server_stat[hostname] += 1
            else:
                server_stat[hostname] = 1
            read_domain_to_ready(ready_queue)
            logger.write_log("Query whois information of domain [" +
                             result_set[RESULT_SET_DOMAIN_COL]["domain"] + "] succeed at server [" +
                             result_set[RESULT_SET_DETAILS_COL][1] + "].",
                             SCREEN | FILE_OUT)
            logger.write_log("%s / %s" % (result_set[RESULT_SET_DOMAIN_COL]["domain"],
                                          result_set[RESULT_SET_DETAILS_COL][1]),
                             FILE_IN_SERVER)
            if result_set[RESULT_SET_DOMAIN_COL]["try_times"] != 0:
                logger.write_log("Query whois information of domain [" +
                                 result_set[RESULT_SET_DOMAIN_COL]["domain"] + "] succeed at server [" +
                                 result_set[RESULT_SET_DETAILS_COL][1] + "] through proxy. " +
                                 str(result_set[RESULT_SET_DOMAIN_COL]["try_times"]),
                                 FILE_ERR)
            logger.write_log(str(result_set[RESULT_SET_DOMAIN_COL]["domain"]) + " / " +
                             repr(result_set[RESULT_SET_DETAILS_COL][0]), FILE_RESULT)
        else:
            domain_set = result_set[RESULT_SET_DOMAIN_COL]
            domain_set["try_times"] += 1
            domain_set["error_msg"].append(result_set[RESULT_SET_DETAILS_COL])
            if domain_set["try_times"] >= MAX_TRY_TIMES:
                report_error(domain_set)
                if result_set[RESULT_SET_DETAILS_COL][1] is not None:
                    logger.write_log("%s / %s" % (result_set[RESULT_SET_DOMAIN_COL]["domain"],
                                                  result_set[RESULT_SET_DETAILS_COL][1]),
                                     FILE_IN_SERVER)
                else:
                    logger.write_log("%s / " % (result_set[RESULT_SET_DOMAIN_COL]["domain"]),
                                     FILE_IN_SERVER)
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
    file_handler["retry"] = open("retry.txt", "w")
    file_handler["in_server"] = open("fin_server2.txt", "w")
    file_handler["whois_err"] = open("pywhoiserror.txt", "w")
    file_handler["result"] = open("result.txt", "w")

    # 创建日志输出线程
    global logger
    out_file_handler_list = [file_handler["out"], file_handler["err"],
                             file_handler["retry"], file_handler["in_server"],
                             file_handler["whois_err"], file_handler["result"]]
    logger = Log(MAX_LENGTH * 10, out_file_handler_list)

    ready_queue = Queue(MAX_LENGTH)
    running_queue = []
    waiting_queue = []
    result_list = Queue(MAX_LENGTH)

    read_domain()
    gene_serverip_buffer()

    # 读取一部分域名进入queue list
    for i in range(MAX_LENGTH):
        if not read_domain_to_ready(ready_queue):
            print "Cannot Initialize Ready Queue."
            return

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
    handle_result_thread.join()

    '''download_threads.append(handle_result_thread)

    # 等待所有线程完成
    for t in download_threads:
        t.join()'''

    item = {"domain": "localhost", "try_times": 0, "server": None, "error_msg": [], "is_error": False}
    ready_queue.put(item)

    logger.write_log("%s: Duration:%s total rows:%s (threads:%s)"
                     % ('Main end', time.time() - st_time, read_count, thread_count), SCREEN)
    logger.write_log("Server Distribution:", SCREEN)
    for key in server_stat.keys():
        logger.write_log("%s - %d" % (key, server_stat[key]), SCREEN)

    logger.write_log("Exiting Main Thread", SCREEN)

    logger.kill()
    logger.get_thread().join()

    file_handler["in"].close()
    file_handler["out"].close()
    file_handler["err"].close()
    file_handler["retry"].close()
    file_handler["in_server"].close()
    file_handler["whois_err"].close()
    file_handler["result"].close()


if __name__ == '__main__':
    main()
