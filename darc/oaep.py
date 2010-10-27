from Crypto.Util.number import long_to_bytes
from Crypto.Hash import SHA

from .helpers import IntegrityError

def _xor_bytes(a, b):
    return ''.join(chr(ord(x[0]) ^ ord(x[1])) for x in zip(a, b))


def MGF1(seed, mask_len, hash=SHA):
    """MGF1 is a Mask Generation Function based on hash function
    """
    T = ''.join(hash.new(seed + long_to_bytes(c, 4)).digest()
                for c in range(1 + mask_len / hash.digest_size))
    return T[:mask_len]


class OAEP(object):
    """Optimal Asymmetric Encryption Padding
    """
    def __init__(self, k, hash=SHA, MGF=MGF1):
        self.k = k
        self.hash = hash
        self.MGF = MGF

    def encode(self, msg, seed, label=''):
        # FIXME: length checks
        if len(msg) > self.k - 2 * self.hash.digest_size - 2:
            raise ValueError('message too long')
        label_hash = self.hash.new(label).digest()
        padding = '\0' * (self.k - len(msg) - 2 * self.hash.digest_size - 2)
        datablock = '%s%s\1%s' % (label_hash, padding, msg)
        datablock_mask = self.MGF(seed, self.k - self.hash.digest_size - 1, self.hash)
        masked_db = _xor_bytes(datablock, datablock_mask)
        seed_mask = self.MGF(masked_db, self.hash.digest_size, self.hash)
        masked_seed = _xor_bytes(seed, seed_mask)
        return '\0%s%s' % (masked_seed, masked_db)

    def decode(self, ciphertext, label=''):
        if len(ciphertext) < self.k:
            ciphertext = ('\0' * (self.k - len(ciphertext))) + ciphertext
        label_hash = self.hash.new(label).digest()
        masked_seed = ciphertext[1:self.hash.digest_size + 1]
        masked_db = ciphertext[-(self.k - self.hash.digest_size - 1):]
        seed_mask = self.MGF(masked_db, self.hash.digest_size, self.hash)
        seed = _xor_bytes(masked_seed, seed_mask)
        datablock_mask = self.MGF(seed, self.k - self.hash.digest_size - 1, self.hash)
        datablock = _xor_bytes(masked_db, datablock_mask)
        label_hash2 = datablock[:self.hash.digest_size]
        data = datablock[self.hash.digest_size:].lstrip('\0')
        if (ciphertext[0] != '\0' or
            label_hash != label_hash2 or
            data[0] != '\1'):
            raise IntegrityError('decryption error')
        return data[1:]


def test():
    from Crypto.Hash import SHA256
    import os
    import random
    oaep = OAEP(256, SHA256)
    for x in range(1000):
        M = os.urandom(random.randint(0, 100))
        EM = oaep.encode(M, os.urandom(32))
        assert len(EM) == oaep.k
        assert oaep.decode(EM) == M

if __name__ == '__main__':
    test()

