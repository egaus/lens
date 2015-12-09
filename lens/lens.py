#! /usr/bin/env python
import logging
import logging.config
import os
import json
import ConfigParser
import LensMongo as mdb
import LensSqlite as sdb
import imp



def getFilesPattern(path, extension="", contains=""):
    allfiles = []
    for path, subdirs, files in os.walk(path):
        for filename in files:
            f = os.path.join(path, filename)
            if filename.endswith(extension) and filename.find(contains) >= 0:
                allfiles.append((f, path, filename))
    return allfiles

class Lens:
    def __init__(self):
        self.dirs = {}
        self.files = {}
        # Figure out where LENS_HOME is going to be.
        if 'LENS_HOME' not in os.environ:
            print 'Environment variable LENS_HOME not set, assuming current \
                working directory'
            self.dirs['home'] = os.curdir
        else:
            self.dirs['home'] = os.environ['LENS_HOME']

        # Validate some of the paths to load configurations
        self.dirs['config'] = os.path.abspath(os.path.join(self.dirs['home'],
                                                           'config'))
        self.files['logconfig'] = os.path.abspath(os.path.join(self.dirs['config'], 'logging.cfg'))
        self.files['lensconfig'] = os.path.abspath(os.path.join(self.dirs['config'], 'lens.cfg'))
        if not os.path.exists(self.dirs['home']):
            raise ValueError('Cannot find directory LENS_HOME:' +
                             self.dirs['home'])
        if not os.path.exists(self.dirs['config']):
            raise ValueError('Cannot find directory LENS_HOME\\config: ' +
                             self.dirs['config'])

        # Load logging configuration
        if os.path.exists(self.files['logconfig']):
            with open(self.files['logconfig'], 'rt') as f:
                config = json.load(f)
            logging.config.dictConfig(config)
        else:
            print 'Cannot find logging config %s, using default logging \
                settings' % (self.files['logconfig'],)

        self.logger = logging.getLogger(__name__)
        self.logger.info('Logging initiated successfully')

        # Load lens configuration
        if os.path.exists(self.files['lensconfig']):
            self.loadLensConfig()
        else:
            logging.basicConfig(level=logging.ERROR)
            print 'Cannot find logging config %s, using default logging \
                settings' % (self.files['logconfig'],)
        self.logger.info('Lens configuration completed successfully')

    def loadLensConfig(self):
        self.logger.info('Attempting to load Lens configuration')
        self.config = ConfigParser.ConfigParser()
        self.config.read(self.files['lensconfig'])

        validatePaths = [('suspicious files', 'files'),
                         ('suspicious files', 'urls'),
                         ('suspicious files', 'pcaps'),
                         ('analysis engines', 'yara'),
                         ('analysis engines', 'analyzers'),
                         ]
        for section, option in validatePaths:
            # Validate each location, set to None if it doesn't exist.
            try:
                self.dirs[option] = self.config.get(section, option)
                self.dirs[option] = self.dirs[option].replace('$LENS_HOME', self.dirs['home'])
                if not os.path.exists(self.dirs[option]):
                    self.logger.warn('Loading lens config, cannot find \
                                     directory %s' % (self.dirs[option],))
                    self.dirs[option] = None
            except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                self.dirs[option] = None

        try:
            dbtype = self.config.get('database', 'dbtype')
            self.logger.info('Loading DB %s' % (dbtype,))
            if dbtype == 'sqlite':
                dbloc = self.config.get('database', 'sqlite_location')
                self.db = sdb.LensSqlite(dbloc)
            elif dbtype == 'mongo':
                dbhost = self.config.get('database', 'dbhost')
                dbport = self.config.get('database', 'dbport')
                dbuser = self.config.get('database', 'dbuser')
                dbpw = self.config.get('database', 'dbpw')
                self.db = mdb.LensMongo(dbhost, dbport, dbuser, dbpw)
            else:
                self.logger.critical('Loading lens config, cannot find \
                                 directory %s' % (self.dirs[option],))
                raise ValueError('Database type unknown %s' % (dbtype,))
        except Exception, e:
            self.logger.critical('Error initializing database: %s' % (str(e), ))
        self.loadAnalyzers()

    def loadAnalyzers(self):
        # https://docs.python.org/2/library/functions.html#getattr
        self.analyzers = {}
        curanalyzers = getFilesPattern(self.dirs['analyzers'], '.py')
        for path_to_analyzer, directory, filename in curanalyzers:
            analyzername = 'analyzers.' + filename.replace('.py','')
            module = imp.load_source(analyzername, path_to_analyzer)
            for item in dir(module):
                # ignore the internal items.
                if not (item.startswith('__') and item.endswith('__')):
                    details = getattr(module, item)()
                    # If it is an analyzer, it must have these things
                    requirements = set(['analyze', 'yara_sigs'])
                    if set(dir(details)).intersection(requirements) == requirements:
                        # instantiate this class because it seems to meet our
                        # requirements of an analyzer
                        if details.yara_sigs is not None:
                            if len(details.yara_sigs) > 0:
                                for sig in details.yara_sigs:
                                    self.analyzers[sig] = getattr(module, item)()
                                    self.logger.info('Successfully registered analyzer: %s:%s' % (filename, item))


            # analyzer = LensAnalyzers.load_source(analyzername, path_to_analyzer)
            # self.analyzers[analyzer.runWhenMatch()] = analyzer

    def findWork(self):
        self.logger.info('checking for work')
        allFiles = getFilesPattern(self.dirs['files'])
        self.logger.info('checking for work in %s found %d files' % (self.dirs['files'],len(allFiles)))

        for myfile in allFiles:
            self.logger.info('Found file %s' % (myfile[2], ))

        allUrls = getFilesPattern(self.dirs['urls'], '.txt')
        for myurl in allUrls:
            self.logger.info('Found urlfile %s' % (myurl[2], ))

        allPcaps = getFilesPattern(self.dirs['pcaps'], '.pcap')
        for mypcap in allPcaps:
            self.logger.info('Found pcap %s' % (mypcap[2], ))

        # check each of the three work queues and handle any new work.

    def run(self):
        self.logger.info('running...')
        self.findWork()
        # if there is work, what kind

    def stop(self):
        self.logger.info('Lens has been stopped')

    def analyze(self):
        """Each file type supplies its own unique analysis techniques"""
        self.logger = logging.getLogger(__name__)
        self.logger.info('Lens.py: analyzing file')
