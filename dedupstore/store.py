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
    class DoesNotExist(KeyError):
        """"""

    class AlreadyExists(KeyError):
        """"""

    IDLE = 'Idle'
    OPEN = 'Open'
    ACTIVE = 'Active'
    VERSION = 'DEDUPSTORE VERSION 1'

    def __init__(self, path):
        self.tid = '-1'
        self.state = Store.IDLE
        if not os.path.exists(path):
            self.create(path)
        self.open(path)
    
    def create(self, path):
        os.mkdir(path)
        open(os.path.join(path, 'version'), 'wb').write(self.VERSION)
        open(os.path.join(path, 'uuid'), 'wb').write(str(uuid.uuid4()))
        open(os.path.join(path, 'tid'), 'wb').write('0')
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
        self.tid = int(open(os.path.join(path, 'tid'), 'r').read())
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

    def commit(self):
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
            fd.write(str(self.tid + 1))
        os.rename(os.path.join(self.path, 'txn-active'),
                  os.path.join(self.path, 'txn-commit'))
        self.recover()

    def apply_txn(self):
        assert os.path.isdir(os.path.join(self.path, 'txn-commit'))
        tid = int(open(os.path.join(self.path, 'txn-commit', 'tid'), 'rb').read())
        assert tid == self.tid + 1
        delete_list = [line.strip() for line in
                       open(os.path.join(self.path, 'txn-commit', 'delete_index'), 'rb').readlines()]
        for name in delete_list:
            path = os.path.join(self.path, 'data', name)
            os.unlink(path)
        write_list = [line.strip() for line in
                      open(os.path.join(self.path, 'txn-commit', 'write_index'), 'rb').readlines()]
        for name in write_list:
            destname = os.path.join(self.path, 'data', name)
            if not os.path.exists(os.path.dirname(destname)):
                os.makedirs(os.path.dirname(destname))
            os.rename(os.path.join(self.path, 'txn-commit', 'write', name), destname)
        with open(os.path.join(self.path, 'tid'), 'wb') as fd:
            fd.write(str(tid))
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

    def _filename(self, ns, id, base=''):
        ns = ns.encode('hex')
        id = id.encode('hex')
        return os.path.join(base, ns, id[:2], id[2:4], id[4:])
            
    def get(self, ns, id):
        """
        """
        path = self._filename(ns, id)
        if path in self.txn_write:
            filename = os.path.join(self.path, 'txn-active', 'write', path)
            return open(filename, 'rb').read()
        if path in self.txn_delete:
            raise Store.DoesNotExist('Object %s:%s does not exist' % (ns.encode('hex'), id.encode('hex')))
        filename = self._filename(ns, id, os.path.join(self.path, 'data'))
        if os.path.exists(filename):
            return open(filename, 'rb').read()
        else:
            raise Store.DoesNotExist('Object %s:%s does not exist' % (ns.encode('hex'), id.encode('hex')))

    def put(self, ns, id, data):
        """
        """
        self.prepare_txn()
        path = self._filename(ns, id)
        filename = self._filename(ns, id, os.path.join(self.path, 'data'))
        if (path in self.txn_write or
           (path not in self.txn_delete and os.path.exists(filename))):
            raise Store.AlreadyExists('Object already exists: %s:%s' % (ns.encode('hex'), id.encode('hex')))
        if path in self.txn_delete:
            self.txn_delete.remove(path)
        if path not in self.txn_write:
            self.txn_write.append(path)
        filename = self._filename(ns, id, os.path.join(self.path, 'txn-active', 'write'))
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as fd:
            fd.write(data)

    def delete(self, ns, id):
        """
        """
        self.prepare_txn()
        path = self._filename(ns, id)
        if path in self.txn_write:
            filename = self._filename(ns, id, os.path.join(self.path, 'txn-active', 'write'))
            self.txn_write.remove(path)
            os.unlink(filename)
        else:
            filename = os.path.join(self.path, 'data', path)
            if os.path.exists(filename):
                self.txn_delete.append(path)
            else:
                raise Store.DoesNotExist('Object does not exist: %s' % hash.encode('hex'))

    def list(self, ns, prefix='', marker=None, max_keys=1000000):
        for x in self.foo(os.path.join(self.path, 'data', ns.encode('hex')), 
                          prefix, marker, '', max_keys):
            yield x
        

    def foo(self, path, prefix, marker, base, max_keys):
        n = 0
        for name in sorted(os.listdir(path)):
            if n >= max_keys:
                return
            dirs = []
            names = []
            id = name.decode('hex')
            if os.path.isdir(os.path.join(path, name)):
                if prefix and not id.startswith(prefix[:len(id)]):
                    continue
                for x in self.foo(os.path.join(path, name),
                                  prefix[len(id):], marker, 
                                  base + id, max_keys - n):
                    yield x
                    n += 1
            else:
                if prefix and not id.startswith(prefix):
                    continue
                if not marker or base + id >= marker:
                    yield base + id
                    n += 1


class StoreTestCase(unittest.TestCase):
    
    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.tmppath, 'store'))

    def tearDown(self):
        shutil.rmtree(self.tmppath)
    
    def test1(self):
        self.assertEqual(self.store.tid, 0)
        self.assertEqual(self.store.state, Store.OPEN)
        self.store.put('SOMENS', 'SOMEID', 'SOMEDATA')
        self.assertRaises(Store.AlreadyExists, lambda: self.store.put('SOMENS', 'SOMEID', 'SOMEDATA'))
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.rollback()
        self.assertRaises(Store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))
        self.assertEqual(self.store.tid, 0)

    def test2(self):
        self.assertEqual(self.store.tid, 0)
        self.assertEqual(self.store.state, Store.OPEN)
        self.store.put('SOMENS', 'SOMEID', 'SOMEDATA')
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.commit()
        self.assertEqual(self.store.tid, 1)
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.delete('SOMENS', 'SOMEID')
        self.assertRaises(Store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))
        self.store.rollback()
        self.assertEqual(self.store.get('SOMENS', 'SOMEID'), 'SOMEDATA')
        self.store.delete('SOMENS', 'SOMEID')
        self.assertRaises(Store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))
        self.store.commit()
        self.assertEqual(self.store.tid, 2)
        self.assertRaises(Store.DoesNotExist, lambda: self.store.get('SOMENS', 'SOMEID'))

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
