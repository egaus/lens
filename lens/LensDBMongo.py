#! /usr/bin/env python
from pymongo import MongoClient


class LensDBMongo:
    def __init__(self, host=None, port=None, user=None, pw=None):
        self.host = host
        self.port = port
        self.user = user
        self.pw = pw
        self.connection = self.connect()

    def connect(self):
        connString = 'mongodb://'
        if self.user is not None and self.user != '' and \
                self.pw is not None and self.pw != '':
            connString = connString + self.user + ':' + self.pw + '@'
        if self.host is None or self.host == '':
            self.host = 'localhost'
        connString = connString + self.host
        if self.port is None or self.port == '':
            self.port = '27017'
            connString = connString + ':' + self.port
        return MongoClient(connString)

    def insert(self, dbname, collection, data):
        if self.connection is not None:
            if len(data) == 1:
                try:
                    result = self.connection[dbname][collection].insert_one(data, bypass_document_validation=True)
                    if result.acknowledged:
                        count = 1
                    else:
                        count = 0
                except Exception, e:
                    count = 0
                    raise e
            elif len(data) > 1:
                try:
                    result = self.connection[dbname][collection].insert_many(data, check_keys=False)
                    count = len(result.inserted_ids)
                except Exception, e:
                    count = 0
                    raise e
            else:
                count = 0
        return count

    def getFiles(self, dbname, collection, query=None):
        # greater than: {"grades.score": {"$gt": 30}}
        # logical AND: {"cuisine": "Italian", "address.zipcode": "10075"}
        # logical OR: {"$or": [{"cuisine": "Italian"}, {"address.zipcode": "10075"}]}
        if self.connection is not None:
            if query is None:
                result = self.connection[dbname][collection].find()
            else:
                result = self.connection[dbname][collection].find(query)

            for document in result:
                print document
        else:
            return None
        return result
