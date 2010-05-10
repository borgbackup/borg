#!/usr/bin/env python
import os
import tempfile
import shutil
import unittest
import sqlite3
import uuid


class SqliteStore(object):
    """
    """

    class DoesNotExist(KeyError):
        """"""

    class AlreadyExists(KeyError):
        """"""

    IDLE = 'Idle'
    OPEN = 'Open'
    ACTIVE = 'Active'
    VERSION = 'DEDUPESTORE VERSION 1'

    def __init__(self, path):
        if not os.path.exists(path):
            self.create(path)
        self.cnx = sqlite3.connect(path)
        self.cursor = self.cnx.cursor()
        self.uuid, self.tid = self.cursor.execute('SELECT uuid, tid FROM system').fetchone()
        self.state = self.OPEN

    def create(self, path):
        cnx = sqlite3.connect(path)
        cnx.execute('PRAGMA auto_vacuum=full')
        cnx.execute('CREATE TABLE objects(ns TEXT NOT NULL, id NOT NULL, data NOT NULL)')
        cnx.execute('CREATE TABLE system(uuid NOT NULL, tid NOT NULL)')
        cnx.execute('INSERT INTO system VALUES(?,?)', (uuid.uuid1().hex, 0))
        cnx.execute('CREATE UNIQUE INDEX objects_pk ON objects(ns, id)')

    def close(self):
        self.cnx.close()

    def commit(self):
        """
        """
        self.cursor.execute('UPDATE system SET tid=tid+1')
        import time
        t = time.time()
        self.cnx.commit()
        print time.time() - t
        self.tid += 1

    def rollback(self):
        """
        """
        self.cnx.rollback()

    def get(self, ns, id):
        """
        """
        self.cursor.execute('SELECT data FROM objects WHERE ns=? and id=?',
                            (ns.encode('hex'), id.encode('hex')))
        row = self.cursor.fetchone()
        if row:
            return str(row[0])
        else:
            raise self.DoesNotExist

    def put(self, ns, id, data):
        """
        """
        try:
            self.cursor.execute('INSERT INTO objects (ns, id, data) '
                                'VALUES(?, ?, ?)',
                                (ns.encode('hex'), id.encode('hex'),
                                sqlite3.Binary(data)))
        except sqlite3.IntegrityError:
            raise self.AlreadyExists

    def delete(self, ns, id):
        """
        """
        self.cursor.execute('DELETE FROM objects WHERE ns=? AND id=?',
                           (ns.encode('hex'), id.encode('hex')))

    def list(self, ns, prefix='', marker=None, max_keys=1000000):
        """
        """
        condition = ''
        if prefix:
            condition += ' AND id LIKE :prefix'
        if marker:
            condition += ' AND id >= :marker'
        args = dict(ns=ns.encode('hex'), prefix=prefix.encode('hex') + '%',
                    marker=marker and marker.encode('hex'))
        for row in self.cursor.execute('SELECT id FROM objects WHERE '
                                'ns=:ns ' + condition + ' LIMIT ' + str(max_keys),
                                args):
            yield row[0].decode('hex')


class SqliteStoreTestCase(unittest.TestCase):
 
    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.store = SqliteStore(os.path.join(self.tmppath, 'store'))

    def tearDown(self):
        shutil.rmtree(self.tmppath)
    
    def test1(self):
        self.assertEqual(self.store.tid, 0)
        self.assertEqual(self.store.state, self.store.OPEN)
        self.store.put('SOMENS', 'SOMEID', 'SOMEDATA')
        self.assertRaises(self.store.AlreadyExists, lambda: self.store.put('SOMENS', 'SOMEID', 'SOMEDATA'))
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.rollback()
        self.assertRaises(self.store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))
        self.assertEqual(self.store.tid, 0)

    def test2(self):
        self.assertEqual(self.store.tid, 0)
        self.assertEqual(self.store.state, self.store.OPEN)
        self.store.put('SOMENS', 'SOMEID', 'SOMEDATA')
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.commit()
        self.assertEqual(self.store.tid, 1)
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.delete('SOMENS', 'SOMEID')
        self.assertRaises(self.store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))
        self.store.rollback()
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.delete('SOMENS', 'SOMEID')
        self.assertRaises(self.store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))
        self.store.commit()
        self.assertEqual(self.store.tid, 2)
        self.assertRaises(self.store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))

    def test_list(self):
        self.store.put('SOMENS', 'SOMEID12', 'SOMEDATA')
        self.store.put('SOMENS', 'SOMEID', 'SOMEDATA')
        self.store.put('SOMENS', 'SOMEID1', 'SOMEDATA')
        self.store.put('SOMENS', 'SOMEID123', 'SOMEDATA')
        self.store.commit()
        self.assertEqual(list(self.store.list('SOMENS', max_keys=3)), 
            ['SOMEID', 'SOMEID1', 'SOMEID12'])
        self.assertEqual(list(self.store.list('SOMENS', marker='SOMEID12')), 
            ['SOMEID12', 'SOMEID123'])
        self.assertEqual(list(self.store.list('SOMENS', prefix='SOMEID1', max_keys=2)), 
            ['SOMEID1', 'SOMEID12'])
        self.assertEqual(list(self.store.list('SOMENS', prefix='SOMEID1', marker='SOMEID12')), 
            ['SOMEID12', 'SOMEID123'])


if __name__ == '__main__':
    unittest.main()
