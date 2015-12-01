#! /usr/bin/env python
import os
from datetime import datetime
import hashlib


class LensFile:

    def __init__(self, pathToFile):
        self.name = os.path.basename(pathToFile)
        self.fullpath = os.path.abspath(pathToFile)
        self.path = os.path.dirname(self.fullpath)
        self.date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
        self.size = os.path.getsize(pathToFile)
        self.filetype = 'unknown'
        self.analyzers = {}

    def getHashes(self):
        with open(self.fullpath) as myfile:
            data = myfile.read()
            self.md5 = hashlib.md5(data).hexdigest()
            self.sha1 = hashlib.sha1(data).hexdigest()
            self.sha256 = hashlib.sha256(data).hexdigest()

    def printFile(self):
        print "Name: " + self.name
        print "FullPath: " + self.fullpath
        print "Path: " + self.path
        print "Date: " + self.date
        print "Size: " + str(self.size)
        print "Type: " + self.filetype
        try:
            print "MD5: " + self.md5
            print "SHA1: " + self.sha1
            print "SHA-256: " + self.sha256
        except AttributeError:
            print "No hash attributes"

    def analyze(self):
        """Each file type supplies its own unique analysis techniques"""
