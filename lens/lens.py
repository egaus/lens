#! /usr/bin/env python
import logging
import logging.config
import os
import json


class Lens:
    def __init__(self):
        if 'LENS_HOME' not in os.environ:
            print 'Environment variable LENS_HOME not set, assuming current \
                working directory'
            self.home = os.curdir
        else:
            self.home = os.environ['LENS_HOME']

        self.config = os.path.abspath(os.path.join(self.home, 'config'))
        self.logconfig = os.path.abspath(os.path.join(self.config,
                                                      'logging.cfg'))
        if not os.path.exists(self.home):
            raise ValueError('Cannot find directory LENS_HOME:' + self.home)
        if not os.path.exists(self.config):
            raise ValueError('Cannot find directory LENS_HOME\\config: ' +
                             self.config)
        if os.path.exists(self.logconfig):
            with open(self.logconfig, 'rt') as f:
                config = json.load(f)
            logging.config.dictConfig(config)
        else:
            logging.basicConfig(level=logging.INFO)
            print 'Cannot find logging config %s, using default logging \
                settings' % (self.logconfig,)

        self.logger = logging.getLogger(__name__)
        self.logger.info('Logging initiated')

    def loadConfig():
        print "loading config"

    def analyze(self):
        """Each file type supplies its own unique analysis techniques"""
        self.logger = logging.getLogger(__name__)
        self.logger.info('Lens.py: analyzing file')
