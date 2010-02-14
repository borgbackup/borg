#!/usr/bin/env python
import fcntl
import tempfile
import logging
import os
import posixpath
import shutil
import unittest

CHUNKSIZE = 256 * 1024

log = logging.getLogger('')

class Repository(object):
    """
    """
    IDLE = 'Idle'
    OPEN = 'Open'
    ACTIVE = 'Active'
    VERSION = 'DEDUPSTORE REPOSITORY VERSION 1'

    def __init__(self, path):
        self.tid = -1
        self.state = Repository.IDLE
        if not os.path.exists(path):
            self.create(path)
        self.open(path)
    
    def create(self, path):
        log.info('Initializing Repository at "%s"' % path)
        os.mkdir(path)
        open(os.path.join(path, 'VERSION'), 'wb').write(self.VERSION)
        open(os.path.join(path, 'tid'), 'wb').write('0')
        os.mkdir(os.path.join(path, 'data'))

    def open(self, path):
        self.path = path
        if not os.path.isdir(path):
            raise Exception('%s Does not look like a repository')
        version_path = os.path.join(path, 'version')
        if not os.path.exists(version_path) or open(version_path, 'rb').read() != self.VERSION:
            raise Exception('%s Does not look like a repository2')
        self.lock_fd = open(os.path.join(path, 'lock'), 'w')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self.tid = int(open(os.path.join(path, 'tid'), 'r').read())
        self.recover()

    def recover(self):
        if os.path.exists(os.path.join(self.path, 'txn-active')):
            self.rollback()
        if os.path.exists(os.path.join(self.path, 'txn-commit')):
            self.commit()
        self.state = Repository.OPEN

    def close(self):
        self.recover()
        self.lock_fd.close()
        self.state = Repository.IDLE

    def commit(self):
        """
        """
        if self.state == Repository.OPEN:
            return
        assert self.state == Repository.ACTIVE
        remove_fd = open(os.path.join(self.path, 'txn-active', 'remove'), 'wb')
        remove_fd.write('\n'.join(self.txn_removed))
        remove_fd.close()
        os.rename(os.path.join(self.path, 'txn-active'),
                  os.path.join(self.path, 'txn-commit'))
        self.commit_txn()

    def commit_txn(self):
        assert os.path.isdir(os.path.join(self.path, 'txn-commit'))
        raise NotImplementedError

    def rollback(self):
        """
        """
        txn_path = os.path.join(self.path, 'txn-active')
        if os.path.exists(txn_path):
            shutil.rmtree(txn_path)
        self.state = Repository.OPEN

    def prepare_txn(self):
        if self.state == Repository.ACTIVE:
            return os.path.join(self.path, 'txn-active')
        elif self.state == Repository.OPEN:
            os.mkdir(os.path.join(self.path, 'txn-active'))
            os.mkdir(os.path.join(self.path, 'txn-active', 'add'))
            open(os.path.join(self.path, 'txn-active', 'tid'), 'wb').write(str(self.tid + 1))
            self.txn_removed = []
            self.state = Repository.ACTIVE
            
    def get_file(self, path):
        """
        """
        if os.path.exists(os.path.join(self.path, 'txn-active', 'add', path)):
            return open(os.path.join(self.path, 'txn-active', 'add', path), 'rb').read()
        elif os.path.exists(os.path.join(self.path, 'data', path)):
            return open(os.path.join(self.path, 'data', path), 'rb').read()
        else:
            raise Exception('FileNotFound: %s' % path)

    def put_file(self, path, data):
        """
        """
        self.prepare_txn()
        if path in self.txn_removed:
            self.txn_removed.remove(path)
        if os.path.exists(os.path.join(self.path, 'txn-active', 'add', path)):
            raise Exception('FileAlreadyExists: %s' % path)
        fd = open(os.path.join(self.path, 'txn-active', 'add', path), 'wb')
        try:
            fd.write(data)
        finally:
            fd.close()

    def delete(self, path):
        """
        """
        self.prepare_txn()
        if os.path.exists(os.path.join(self.path, 'txn-active', 'add', path)):
            os.unlink(os.path.join(self.path, 'txn-active', 'add', path))
        elif os.path.exists(os.path.join(self.path, 'data', path)):
            self.txn_removed.append(path)
        else:
            raise Exception('FileNotFound: %s' % path)

    def listdir(self, path):
        """
        """
        entries = set(os.listdir(os.path.join(self.path, 'data', path)))
        if self.state == Repository.ACTIVE:
            txn_entries = set(os.listdir(os.path.join(self.path, 'txn-active', 'add', path)))
            entries = entries.union(txn_entries)
            for e in entries:
                if posixpath.join(path, e) in self.txn_removed:
                    entries.remove(e)
        return list(entries)

    def mkdir(self, path):
        """
        """

    def rmdir(self, path):
        """
        """

class RepositoryTestCase(unittest.TestCase):
    
    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.repo = Repository(os.path.join(self.tmppath, 'repo'))

    def tearDown(self):
        shutil.rmtree(self.tmppath)
    
    def test1(self):
        self.assertEqual(self.repo.tid, 0)
        self.assertEqual(self.repo.state, Repository.OPEN)
        self.assertEqual(self.repo.listdir(''), [])
        self.repo.put_file('foo', 'SOMEDATA')
        self.assertRaises(Exception, lambda: self.repo.put_file('foo', 'SOMETHINGELSE'))
        self.assertEqual(self.repo.get_file('foo'), 'SOMEDATA')
        self.assertEqual(self.repo.listdir(''), ['foo'])
        self.repo.rollback()
        self.assertEqual(self.repo.listdir(''), [])

    def test2(self):
        self.repo.put_file('foo', 'SOMEDATA')
        self.repo.put_file('bar', 'SOMEDATAbar')
        self.assertEqual(self.repo.listdir(''), ['foo', 'bar'])
        self.assertEqual(self.repo.get_file('foo'), 'SOMEDATA')
        self.repo.delete('foo')
        self.assertRaises(Exception, lambda: self.repo.get_file('foo'))
        self.assertEqual(self.repo.listdir(''), ['bar'])
        self.assertEqual(self.repo.state, Repository.ACTIVE)
        self.repo.commit()

if __name__ == '__main__':
    unittest.main()
