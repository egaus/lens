#! /usr/bin/env python
import logging
import logging.handlers
import os
import time


class Lens:
    def __init__(self):
        if 'LENS_HOME' not in os.environ:
            print "Environment variable LENS_HOME not set, assuming current \
                working directory"
            self.home = os.curdir()
        else:
            self.home = os.environ['LENS_HOME']

        self.var = os.path.abspath(os.path.join(self.home, 'var'))
        self.log = os.path.abspath(os.path.join(self.var, 'log'))
        self.logfile = os.path.abspath(os.path.join(self.log, 'lensd.log'))
        if not os.path.exists(self.home):
            raise ValueError('Cannot find directory LENS_HOME:' + self.home)
        if not os.path.exists(self.var):
            raise ValueError('Cannot find directory LENS_HOME\\var: ' + self.var)
        if not os.path.exists(self.log):
            raise ValueError('Cannot find directory LENS_HOME\\var\log: ' + \
                             self.log)

        self.logger = logging.getLogger('LensLogger')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.handlers.RotatingFileHandler(self.logfile,
                                                       maxBytes=(1024*1024*8))
        # logging.Formatter.converter = time.gmtime
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s|%(levelname)s|%(message)s",
                          "%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.logger.debug('Lens.py: This message should go to the log file')


    def loadConfig():
        print "loading config"

    def analyze(self):
        """Each file type supplies its own unique analysis techniques"""
        logging.debug('Lens.py: analyzing file')
