from time import ctime
import threading
from log import Log


class BaseThread(threading.Thread):
    def __init__(self, func, args, name=''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args
        self.res = None
        self.logger = Log.get_instance()

    def getResult(self):
        return self.res

    def run(self):
        self.logger.write_log('starting %s at: %s' %(self.name, ctime()), 1)
        self.res = apply(self.func, self.args)
        self.logger.write_log('%s finished at: %s' %(self.name, ctime()), 1)
