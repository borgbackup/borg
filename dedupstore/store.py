#!/usr/bin/env python
import os
import fcntl
import hashlib
import tempfile
import shutil
import unittest
import uuid


class Store(object):
    """
    """
    IDLE = 'Idle'
    OPEN = 'Open'
    ACTIVE = 'Active'
    VERSION = 'DEDUPSTORE VERSION 1'

    def __init__(self, path):
        self.tid = ''
        self.state = Store.IDLE
        if not os.path.exists(path):
            self.create(path)
        self.open(path)
    
    def create(self, path):
        os.mkdir(path)
        open(os.path.join(path, 'version'), 'wb').write(self.VERSION)
        open(os.path.join(path, 'uuid'), 'wb').write(str(uuid.uuid4()))
        open(os.path.join(path, 'tid'), 'wb').write('')
        os.mkdir(os.path.join(path, 'data'))

    def open(self, path):
        self.path = path
        if not os.path.isdir(path):
            raise Exception('%s Does not look like a store')
        version_path = os.path.join(path, 'version')
        if not os.path.exists(version_path) or open(version_path, 'rb').read() != self.VERSION:
            raise Exception('%s Does not look like a store2')
        self.uuid = open(os.path.join(path, 'uuid'), 'rb').read()
        self.lock_fd = open(os.path.join(path, 'lock'), 'w')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self.tid = open(os.path.join(path, 'tid'), 'r').read()
        self.recover()

    def recover(self):
        if os.path.exists(os.path.join(self.path, 'txn-active')):
            shutil.rmtree(os.path.join(self.path, 'txn-active'))
        if os.path.exists(os.path.join(self.path, 'txn-commit')):
            self.apply_txn()
        if os.path.exists(os.path.join(self.path, 'txn-applied')):
            shutil.rmtree(os.path.join(self.path, 'txn-applied'))
        self.state = Store.OPEN
        self.txn_delete = []
        self.txn_write = []

    def close(self):
        self.recover()
        self.lock_fd.close()
        self.state = Store.IDLE

    def commit(self, tid):
        """
        """
        if self.state == Store.OPEN:
            return
        assert self.state == Store.ACTIVE
        with open(os.path.join(self.path, 'txn-active', 'delete_index'), 'wb') as fd:
            fd.write('\n'.join(self.txn_delete))
        with open(os.path.join(self.path, 'txn-active', 'write_index'), 'wb') as fd:
            fd.write('\n'.join(self.txn_write))
        with open(os.path.join(self.path, 'txn-active', 'tid'), 'wb') as fd:
            fd.write(tid)
        os.rename(os.path.join(self.path, 'txn-active'),
                  os.path.join(self.path, 'txn-commit'))
        self.recover()

    def apply_txn(self):
        assert os.path.isdir(os.path.join(self.path, 'txn-commit'))
        tid = open(os.path.join(self.path, 'txn-commit', 'tid'), 'rb').read()
        delete_list = [line.strip() for line in
                       open(os.path.join(self.path, 'txn-commit', 'delete_index'), 'rb').readlines()]
        for name in delete_list:
            path = os.path.join(self.path, 'objects', name)
            os.unlink(path)
        write_list = [line.strip() for line in
                      open(os.path.join(self.path, 'txn-commit', 'write_index'), 'rb').readlines()]
        for name in write_list:
            destname = os.path.join(self.path, 'objects', name)
            if not os.path.exists(os.path.dirname(destname)):
                os.makedirs(os.path.dirname(destname))
            os.rename(os.path.join(self.path, 'txn-commit', 'write', name), destname)
        with open(os.path.join(self.path, 'tid'), 'wb') as fd:
            fd.write(tid)
        os.rename(os.path.join(self.path, 'txn-commit'),
                  os.path.join(self.path, 'txn-applied'))
        shutil.rmtree(os.path.join(self.path, 'txn-applied'))
        self.tid = tid

    def rollback(self):
        """
        """
        self.recover()

    def prepare_txn(self):
        if self.state == Store.ACTIVE:
            return os.path.join(self.path, 'txn-active')
        elif self.state == Store.OPEN:
            os.mkdir(os.path.join(self.path, 'txn-active'))
            os.mkdir(os.path.join(self.path, 'txn-active', 'write'))
            self.state = Store.ACTIVE

    def _filename(self, hash, base=''):
        hex = hash.encode('hex')
        return os.path.join(base, hex[:2], hex[2:4], hex[4:])
            
    def get(self, hash):
        """
        """
        path = self._filename(hash)
        if path in self.txn_write:
            filename = os.path.join(self.path, 'txn-active', 'write', path)
            return open(filename, 'rb').read()
        filename = self._filename(hash, os.path.join(self.path, 'objects'))
        if os.path.exists(filename):
            return open(filename, 'rb').read()
        else:
            raise Exception('Object %s does not exist' % hash.encode('hex'))

    def put(self, data, hash=None):
        """
        """
        if not hash:
            hash = hashlib.sha1(data).digest()
        self.prepare_txn()
        path = self._filename(hash)
        filename = self._filename(hash, os.path.join(self.path, 'objects'))
        if (path in self.txn_write or
           (path not in self.txn_delete and os.path.exists(filename))):
            raise Exception('Object already exists: %s' % hash.encode('hex'))
        if path in self.txn_delete:
            self.txn_delete.remove(path)
        if path not in self.txn_write:
            self.txn_write.append(path)
        filename = self._filename(hash, os.path.join(self.path, 'txn-active', 'write'))
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as fd:
            fd.write(data)
        return hash

    def delete(self, hash):
        """
        """
        self.prepare_txn()
        path = self._filename(hash)
        if path in self.txn_write:
            self.txn_write.remove(path)
            os.unlink(filename)
        else:
            filename = os.path.join(self.path, 'objects', path)
            if os.path.exists(filename):
                self.txn_delete.append(path)
            else:
                raise Exception('Object does not exist: %s' % hash.encode('hex'))


class StoreTestCase(unittest.TestCase):
    
    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.tmppath, 'store'))

    def tearDown(self):
        shutil.rmtree(self.tmppath)
    
    def test1(self):
        self.assertEqual(self.store.tid, '')
        self.assertEqual(self.store.state, Store.OPEN)
        SOMEDATA_hash = self.store.put('SOMEDATA')
        self.assertRaises(Exception, lambda: self.store.put('SOMEDATA'))
        self.assertEqual(self.store.get(SOMEDATA_hash), 'SOMEDATA')
        self.store.rollback()
        self.assertRaises(Exception, lambda: self.store.get('SOMEDATA'))
        self.assertEqual(self.store.tid, '')

    def test2(self):
        self.assertEqual(self.store.tid, '')
        self.assertEqual(self.store.state, Store.OPEN)
        SOMEDATA_hash = self.store.put('SOMEDATA')
        self.assertEqual(self.store.get(SOMEDATA_hash), 'SOMEDATA')
        self.store.commit(SOMEDATA_hash)
        self.assertEqual(self.store.tid, SOMEDATA_hash)
        self.assertEqual(self.store.get(SOMEDATA_hash), 'SOMEDATA')
        self.store.delete(SOMEDATA_hash)
        self.assertRaises(Exception, lambda: self.store.get('SOMEDATA'))
        self.store.rollback()
        self.assertEqual(self.store.get(SOMEDATA_hash), 'SOMEDATA')
        self.store.delete(SOMEDATA_hash)
        self.assertRaises(Exception, lambda: self.store.get('SOMEDATA'))
        self.store.commit('Something Else')
        self.assertEqual(self.store.tid, 'Something Else')
        self.assertRaises(Exception, lambda: self.store.get('SOMEDATA'))


if __name__ == '__main__':
    unittest.main()
