#! /usr/bin/env python
import LensDBMongo as mdb
import LensDBSqlite as sdb

def replaceKeyValue(replaceThis, withThis, data):
    new = {}
    for k, v in data.iteritems():
        if isinstance(v, dict):
            v = replaceKeyValue(replaceThis, withThis, v)
        new[k.replace(replaceThis, withThis)] = v
    return new


class LensDB:
    def __init__(self, dbtype, dbname=None, dbpath=None, host=None, port=None,
                 user=None, pw=None):
        self.dbtype = dbtype
        if self.dbtype == 'mongo':
            self.db = mdb.LensDBMongo(dbname=dbname, host=host, port=port,
                                      user=user, pw=pw)
        elif self.dbtype == 'sqlite':
            self.db = sdb.LensSqlite(dbpath)
        else:
            raise ValueError('Invalid database type %s' % (dbtype,))

    def insert(self, datatype, data):
        if self.dbtype == 'sqlite':
            count = self.db.insert(datatype, data)
        else:
            newdata = replaceKeyValue('.', '<&#046;>', data)
            count = self.db.insert(datatype, newdata)

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
                origDocument = replaceKeyValue('<&#046;>', '.', document)
                print origDocument
        else:
            return None
        return result
