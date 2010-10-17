#!/usr/bin/env python
import os
import tempfile
import shutil
import unittest
import sqlite3
import uuid
import fcntl


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
    BAND_LIMIT = 1 * 1024 * 1024

    def __init__(self, path):
        self.read_fd = None
        self.write_fd = None
        if not os.path.exists(path):
            self.create(path)
        self.open(path)

    def open(self, path):
        if not os.path.isdir(path):
            raise Exception('%s Does not look like a store')
        db_path = os.path.join(path, 'dedupestore.db')
        if not os.path.exists(db_path):
            raise Exception('%s Does not look like a store2')
        self.lock_fd = open(os.path.join(path, 'lock'), 'w')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self.path = path
        self.cnx = sqlite3.connect(db_path)
        self.cursor = self.cnx.cursor()
        self._begin()

    def _begin(self):
        if self.read_fd:
            self.read_fd.close()
            self.read_fd = None
        if self.write_fd:
            self.write_fd.close()
            self.write_fd = None
        row = self.cursor.execute('SELECT uuid, tid, nextband, version, '
                                  'bandlimit FROM system').fetchone()
        self.uuid, self.tid, self.nextband, version, self.bandlimit = row
        assert version == 1
        self.state = self.OPEN
        self.read_band = None
        self.write_band = None
        self.to_delete = set()
        band = self.nextband
        while os.path.exists(self.band_filename(band)):
            os.unlink(self.band_filename(band))
            band += 1

    def create(self, path):
        os.mkdir(path)
        os.mkdir(os.path.join(path, 'bands'))
        cnx = sqlite3.connect(os.path.join(path, 'dedupestore.db'))
        cnx.execute('CREATE TABLE objects(ns TEXT NOT NULL, id NOT NULL, '
                    'band NOT NULL, offset NOT NULL, size NOT NULL)')
        cnx.execute('CREATE TABLE system(uuid NOT NULL, tid NOT NULL, '
                    'nextband NOT NULL, version NOT NULL, bandlimit NOT NULL)')
        cnx.execute('INSERT INTO system VALUES(?,?,?,?,?)',
                    (uuid.uuid1().hex, 0, 0, 1, self.BAND_LIMIT))
        cnx.execute('CREATE UNIQUE INDEX objects_pk ON objects(ns, id)')

    def close(self):
        self.rollback()
        self.cnx.close()
        self.lock_fd.close()
        os.unlink(os.path.join(self.path, 'lock'))

    def commit(self):
        """
        """
        self.band = None
        for b in self.to_delete:
            objects = self.cursor.execute('SELECT ns, id, offset, size '
                                          'FROM objects WHERE band=? ORDER BY offset',
                                          (b,)).fetchall()
            for o in objects:
                band, offset, size = self.store_data(self.retrieve_data(b, *o[2:]))
                self.cursor.execute('UPDATE objects SET band=?, offset=?, size=? '
                                    'WHERE ns=? AND id=?', (band, offset, size, o[0], o[1]))
            self.cnx.commit()
            os.unlink(self.band_filename(b))
        self.cursor.execute('UPDATE system SET tid=tid+1, nextband=?',
                            (self.nextband,))
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

    def band_filename(self, band):
        return os.path.join(self.path, 'bands', str(band / 1000), str(band))

    def retrieve_data(self, band, offset, size):
        if self.read_band != band:
            self.read_band = band
            if self.read_fd:
                self.read_fd.close()
            self.read_fd = open(self.band_filename(band), 'rb')
        self.read_fd.seek(offset)
        return self.read_fd.read(size)

    def store_data(self, data):
        if self.write_band is None:
            self.write_band = self.nextband
            self.nextband += 1
            if self.write_band % 1000 == 0:
                os.mkdir(os.path.join(self.path, 'bands', str(self.write_band / 1000)))
            assert not os.path.exists(self.band_filename(self.write_band))
            self.write_fd = open(self.band_filename(self.write_band), 'ab')
        band = self.write_band
        offset = self.write_fd.tell()
        self.write_fd.write(data)
        if offset + len(data) > self.bandlimit:
            self.write_band = None
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
