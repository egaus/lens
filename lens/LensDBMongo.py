#! /usr/bin/env python
from pymongo import MongoClient
import datetime


class LensDBMongo:
    def __init__(self, dbname=None, host=None, port=None, user=None, pw=None):
        self.host = host
        self.port = port
        self.user = user
        self.pw = pw
        self.dbname = dbname
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

    def insert(self, collection, data):
        if self.connection is not None:
            # when supporting multiple writes in one DB call, use bulk_write
            # http://api.mongodb.org/python/current/api/pymongo/collection.html#pymongo.collection.Collection.update_many
            for key in data:
                item = data[key]
                try:
                    # result = self.connection[self.dbname][collection].insert_one(data, bypass_document_validation=True)
                    import pdb; pdb.set_trace()
                    item['lastseen'] = datetime.datetime.utcnow()
                    entryToInsert = {
                        '$set': item,
                        '$setOnInsert': { 'firstSeen': datetime.datetime.utcnow() },
                        '$inc':{'timesSeen':1}
                    }
                    if 'lastSeenFileName' in item.keys():
                        entryToInsert['$addToSet'] = {'filename':item['lastSeenFileName']}
                    result = self.connection[self.dbname][collection].update_one({'_id':key}, entryToInsert, upsert=True)
                    if result.acknowledged:
                        count = 1
                    else:
                        count = 0
                except Exception, e:
                    count = 0
                    raise e
        return count

    def getFiles(self, collection, query=None):
        # greater than: {"grades.score": {"$gt": 30}}
        # logical AND: {"cuisine": "Italian", "address.zipcode": "10075"}
        # logical OR: {"$or": [{"cuisine": "Italian"}, {"address.zipcode": "10075"}]}
        if self.connection is not None:
            if query is None:
                result = self.connection[self.dbname][collection].find()
            else:
                result = self.connection[self.dbname][collection].find(query)

            for document in result:
                print document
        else:
            return None
        return result
