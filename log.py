# coding=utf-8

from Queue import Queue
import sys

import BaseThread


class Log(object):
    __instance = None

    def __init__(self, max_size, handler_list, is_daemon=False):
        Log.__instance.string_pool = Queue(max_size)
        Log.__instance.handler_list = handler_list
        Log.__instance.thread = BaseThread.BaseThread(display_log,
                                                      (self.string_pool, self.handler_list),
                                                      'log_thread')
        if is_daemon:
            Log.__instance.thread.setDaemon(True)
        Log.__instance.thread.start()

    def __new__(cls, *arg, **kwargs):
        if Log.__instance is None:
            Log.__instance = object.__new__(cls, *arg, **kwargs)

            print str(arg) + ", " + str(kwargs) + ", id=" + str(id(Log.__instance))
            return Log.__instance
        else:
            return None

    # 完成一条内容的输出，输出内容不保证即刻执行
    # flag表示待输出的设备，0为退出线程，1为输出到屏幕
    def write_log(self, content, flag):
        string_set = {"flag": flag, "content": content}
        self.string_pool.put(string_set)

    def kill(self):
        item = {"flag": 0x0, "content": None}
        self.string_pool.put(item)

    def get_thread(self):
        return self.thread

    @staticmethod
    def get_instance():
        return Log.__instance


# 向屏幕/文件输出信息的线程体
def display_log(string_pool, file_handler):
    buf = ['']
    for i in range(len(file_handler) + 1):
        buf.append('')
    while True:
        string_set = string_pool.get()
        if string_set["flag"] == 0:
            for i, fh in enumerate(file_handler):
                fh.write(buf[i + 1])
            break
        else:
            if string_set["flag"] & 0x1 == 0x1:
                print string_set["content"]
            for i, fh in enumerate(file_handler):
                flag_bit = 2 ** (i + 1)
                if string_set["flag"] & flag_bit == flag_bit:
                    buf[i + 1] += string_set["content"] + '\n'
                    if sys.getsizeof(buf[i + 1]) >= 4037:
                        fh.write(buf[i + 1])
                        buf[i + 1] = ''
