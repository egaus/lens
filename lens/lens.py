#! /usr/bin/env python
import logging
import logging.config
import os
import json
import ConfigParser
import LensDBMongo as mdb
import LensSqlite as sdb
import imp
import hashlib
import yara
from sets import Set
import pprint

def getFilesPattern(path, extension="", contains="", extension_exclude=None,
                    doesnotcontain=None):
    allfiles = []
    for path, subdirs, files in os.walk(path):
        for filename in files:
            f = os.path.join(path, filename)
            addFile = True
            if filename.endswith(extension) and filename.find(contains) >= 0:
                # Check excludes
                if extension_exclude is not None:
                    if filename.endswith(extension_exclude) > 0:
                        addFile = False

                if doesnotcontain is not None:
                    if filename.find(doesnotcontain) > 0:
                        addFile = False

                if addFile:
                    allfiles.append((f, path, filename))
    return allfiles

def getFileHashes(pathtofile):
    if os.path.isfile(pathtofile):
        with open(pathtofile, 'rb') as file_to_hash:
            filedata = file_to_hash.read()
            md5 = hashlib.md5(filedata).hexdigest()
            sha1 = hashlib.sha1(filedata).hexdigest()
            sha256 = hashlib.sha256(filedata).hexdigest()
            return (md5, sha1, sha256)
    return None


def yaraMatch(filename, yararules):
    yararules.match(filename)
    return [x.rule for x in yararules.match(filename)]


def generateYaraIndex(indexfile, ruledir):
    yararules = getFilesPattern(ruledir, contains=".yar",
                                extension_exclude='index.yar')
    f = open(indexfile, 'w')
    for rule in yararules:
        f.write('include "' + rule[0] + '"\n')
    f.close()


class Lens:
    def __init__(self):
        self.dirs = {}
        self.files = {}
        # Figure out where LENS_HOME is going to be.
        if 'LENS_HOME' not in os.environ:
            print 'Environment variable LENS_HOME not set, assuming one' + \
                ' parent directory of this file %s is LENS_HOME' % __file__
            self.dirs['home'] = os.path.abspath(os.path.join(
                                os.path.dirname(__file__), os.pardir))
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

        yaraindexfile = os.path.join(self.dirs['yara'], 'index.yar')
        generateYaraIndex(yaraindexfile, self.dirs['yara'])
        self.yararules = yara.compile(yaraindexfile)


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
                self.db = mdb.LensDBMongo(dbhost, dbport, dbuser, dbpw)
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
        self.analyzer_sig_exclude = {}
        self.analyzer_sig_include = {}
        curanalyzers = getFilesPattern(self.dirs['analyzers'], extension='.py')
        for path_to_analyzer, directory, filename in curanalyzers:
            analyzername = 'analyzers.' + filename.replace('.py','')
            module = imp.load_source(analyzername, path_to_analyzer)
            for item in dir(module):
                # ignore the internal items.
                if not (item.startswith('__') and item.endswith('__')):
                    try:
                        details = getattr(module, item)()
                        # If it is an analyzer, it must have these things
                        requirements = set(['analyze', 'yara_sigs'])
                        if set(dir(details)).intersection(requirements) == requirements:
                            # instantiate this class because it seems to meet our
                            # requirements of an analyzer
                            if details.yara_sigs is not None:
                                # Process Yara sigs to include
                                if len(details.yara_sigs) > 0:
                                    for sig in details.yara_sigs:
                                        if sig not in self.analyzer_sig_include.keys():
                                            self.analyzer_sig_include[sig] = []
                                        self.analyzer_sig_include[sig].append(item)
                                        self.analyzers[item] = getattr(module, item)()
                                        self.logger.info('Successfully registered analyzer: %s:%s' % (filename, item))
                                # Process Yara sigs to exclude
                                if len(details.yara_sigs_exclude) > 0:
                                    for sig in details.yara_sigs_exclude:
                                        if sig not in self.analyzer_sig_exclude.keys():
                                            self.analyzer_sig_exclude[sig] = []
                                        self.analyzer_sig_exclude[sig].append(item)
                                        self.logger.info('Successfully excluding analyzer: %s:%s' % (filename, item))

                    except (TypeError, AttributeError):
                        pass

    def logChange(self, message):
        self.logger.info(message)

    def findWork(self):
        self.logger.info('checking for work')
        allFiles = getFilesPattern(self.dirs['files'])
        self.logger.info('checking for work in %s found %d files' % (self.dirs['files'],len(allFiles)))

        for myfile in allFiles:
            self.logger.info('Found file %s' % (myfile[2], ))
            self.analyzeFile(myfile)

        allUrls = getFilesPattern(self.dirs['urls'], '.txt')
        for myurl in allUrls:
            self.logger.info('Found urlfile %s' % (myurl[2], ))
            # call function to process urlfile
            # if there are url's to process, recommend multiprocessing
            # for concurrent downloads

        allPcaps = getFilesPattern(self.dirs['pcaps'], '.pcap')
        for mypcap in allPcaps:
            self.logger.info('Found pcap %s' % (mypcap[2], ))
            # call function to parse pcap
            # recommend multiprocessing to speed processing of large .pcaps

        # check each of the three work queues and handle any new work.


    def analyzeFile(self, myfile):
        import pdb; pdb.set_trace()
        pathtofile = myfile[0]
        hashes = getFileHashes(pathtofile)
        yaramatches = yaraMatch(pathtofile, self.yararules)
        print pathtofile
        print hashes
        print yaramatches
        print self.analyzers
        toRun = []
        toExclude = []
        for sig in yaramatches:
            if sig in self.analyzer_sig_include.keys():
                toRun = toRun + self.analyzer_sig_include[sig]
            if sig in self.analyzer_sig_exclude.keys():
                toExclude = toExclude + self.analyzer_sig_exclude[sig]
        toRunSet = Set(toRun)
        toRunSet.difference(Set(toExclude))

        # This is single threaded, to multi-process later
        allResults = {}
        allResults[hashes[1]] = {}
        allResults[hashes[1]]['filename'] = myfile[2]
        allResults[hashes[1]]['size'] = os.stat(myfile[0]).st_size
        allResults[hashes[1]]['path'] = myfile[1]
        allResults[hashes[1]]['md5'] = hashes[0]
        allResults[hashes[1]]['sha256'] = hashes[2]

        for analyzer in toRunSet:
            result = self.analyzers[analyzer].analyze(filepath=pathtofile)
            allResults[hashes[1]][analyzer] = result

        pprint.pprint(allResults)
        self.db.insert('test', 'files',  allResults)


    def run(self):
        self.logger.info('running...')
        self.findWork()
        # if there is work, what kind

    def analyze(self):
        """Each file type supplies its own unique analysis techniques"""
        self.logger = logging.getLogger(__name__)
        self.logger.info('Lens.py: analyzing file')
