#!/usr/bin/env python
import os
import tempfile
import shutil
import unittest
import sqlite3
import uuid


class BandStore(object):
    """
    """

    class DoesNotExist(KeyError):
        """"""

    class AlreadyExists(KeyError):
        """"""

    IDLE = 'Idle'
    OPEN = 'Open'
    ACTIVE = 'Active'
    BAND_LIMIT = 1024 * 1024 * 10

    def __init__(self, path):
        if not os.path.exists(path):
            self.create(path)
        self.path = path
        self.cnx = sqlite3.connect(os.path.join(path, 'index.db'))
        self.cursor = self.cnx.cursor()
        self._begin()

    def _begin(self):
        self.uuid, self.tid, self.next_band = self.cursor.execute('SELECT uuid, tid, nextband FROM system').fetchone()
        self.state = self.OPEN
        self.band = None
        self.to_delete = set()

    def create(self, path):
        os.mkdir(path)
        os.mkdir(os.path.join(path, 'bands'))
        cnx = sqlite3.connect(os.path.join(path, 'index.db'))
        cnx.execute('CREATE TABLE objects(ns TEXT NOT NULL, id NOT NULL, '
                    'band NOT NULL, offset NOT NULL, size NOT NULL)')
        cnx.execute('CREATE TABLE system(uuid NOT NULL, tid NOT NULL, nextband NOT NULL)')
        cnx.execute('INSERT INTO system VALUES(?,?,?)', (uuid.uuid1().hex, 0, 0))
        cnx.execute('CREATE UNIQUE INDEX objects_pk ON objects(ns, id)')

    def close(self):
        self.cnx.close()

    def commit(self):
        """
        """
        self.band = None
        for b in self.to_delete:
            objects = self.cursor.execute('SELECT ns, id, offset, size '
                                          'FROM objects WHERE band=?', (b,)).fetchall()
            for o in objects:
                band, offset, size = self.store_data(self.retrieve_data(b, *o[2:]))
                self.cursor.execute('UPDATE objects SET band=?, offset=?, size=? '
                                    'WHERE ns=? AND id=?', (band, offset, size, o[0], o[1]))
            os.unlink(os.path.join(self.path, 'bands', str(b)))
        self.cursor.execute('UPDATE system SET tid=tid+1, nextband=?',
                            (self.next_band,))
        self.cnx.commit()
        self.tid += 1
        self._begin()

    def rollback(self):
        """
        """
        self.cnx.rollback()
        self._begin()

    def get(self, ns, id):
        """
        """
        self.cursor.execute('SELECT band, offset, size FROM objects WHERE ns=? and id=?',
                            (ns.encode('hex'), id.encode('hex')))
        row = self.cursor.fetchone()
        if row:
            return self.retrieve_data(*row)
        else:
            raise self.DoesNotExist

    def retrieve_data(self, band, offset, size):
        with open(os.path.join(self.path, 'bands', str(band)), 'rb') as fd:
            fd.seek(offset)
            return fd.read(size)

    def store_data(self, data):
        if self.band is None:
            self.band = self.next_band
            assert not os.path.exists(os.path.join(self.path, 'bands', str(self.band)))
            self.next_band += 1
        band = self.band
        with open(os.path.join(self.path, 'bands', str(band)), 'ab') as fd:
            offset = fd.tell()
            fd.write(data)
            if offset + len(data) > self.BAND_LIMIT:
                self.band = None
        return band, offset, len(data)

    def put(self, ns, id, data):
        """
        """
        try:
            band, offset, size = self.store_data(data)
            self.cursor.execute('INSERT INTO objects (ns, id, band, offset, size) '
                                'VALUES(?, ?, ?, ?, ?)',
                                (ns.encode('hex'), id.encode('hex'),
                                band, offset, size))
        except sqlite3.IntegrityError:
            raise self.AlreadyExists

    def delete(self, ns, id):
        """
        """
        self.cursor.execute('SELECT band FROM objects WHERE ns=? and id=?',
                            (ns.encode('hex'), id.encode('hex')))
        row = self.cursor.fetchone()
        if not row:
            raise self.DoesNotExist
        self.cursor.execute('DELETE FROM objects WHERE ns=? AND id=?',
                           (ns.encode('hex'), id.encode('hex')))
        self.to_delete.add(row[0])

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


class BandStoreTestCase(unittest.TestCase):

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.store = BandStore(os.path.join(self.tmppath, 'store'))

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
