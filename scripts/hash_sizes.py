"""
Compute hashtable sizes with nices properties
- prime sizes (for small to medium sizes)
- 2 prime-factor sizes (for big sizes)
- fast growth for small sizes
- slow growth for big sizes

Note:
     this is just a tool for developers.
     within borgbackup, it is just used to generate hash_sizes definition for _hashindex.c.
"""

from collections import namedtuple

K, M, G = 2**10, 2**20, 2**30

# hash table size (in number of buckets)
start, end_p1, end_p2 = 1 * K, 127 * M, 2 * G - 10 * M  # stay well below 2^31 - 1

Policy = namedtuple("Policy", "upto grow")

policies = [
    # which growth factor to use when growing a hashtable of size < upto
    # grow fast (*2.0) at the start so we do not have to resize too often (expensive).
    # grow slow (*1.1) for huge hash tables (do not jump too much in memory usage)
    Policy(256*K, 2.0),
    Policy(2*M, 1.7),
    Policy(16*M, 1.4),
    Policy(128*M, 1.2),
    Policy(2*G-1, 1.1),
]


# slightly modified version of:
# http://www.macdevcenter.com/pub/a/python/excerpt/pythonckbk_chap1/index1.html?page=2
def eratosthenes():
    """Yields the sequence of prime numbers via the Sieve of Eratosthenes."""
    D = {}  # map each composite integer to its first-found prime factor
    q = 2  # q gets 2, 3, 4, 5, ... ad infinitum
    while True:
        p = D.pop(q, None)
        if p is None:
            # q not a key in D, so q is prime, therefore, yield it
            yield q
            # mark q squared as not-prime (with q as first-found prime factor)
            D[q * q] = q
        else:
            # let x <- smallest (N*p)+q which wasn't yet known to be composite
            # we just learned x is composite, with p first-found prime factor,
            # since p is the first-found prime factor of q -- find and mark it
            x = p + q
            while x in D:
                x += p
            D[x] = p
        q += 1


def two_prime_factors(pfix=65537):
    """Yields numbers with 2 prime factors pfix and p."""
    for p in eratosthenes():
        yield pfix * p


def get_grow_factor(size):
    for p in policies:
        if size < p.upto:
            return p.grow


def find_bigger_prime(gen, i):
    while True:
        p = next(gen)
        if p >= i:
            return p


def main():
    sizes = []
    i = start

    gen = eratosthenes()
    while i < end_p1:
        grow_factor = get_grow_factor(i)
        p = find_bigger_prime(gen, i)
        sizes.append(p)
        i = int(i * grow_factor)

    gen = two_prime_factors()  # for lower ram consumption
    while i < end_p2:
        grow_factor = get_grow_factor(i)
        p = find_bigger_prime(gen, i)
        sizes.append(p)
        i = int(i * grow_factor)

    print("""\
static int hash_sizes[] = {
    %s
};
""" % ', '.join(str(size) for size in sizes))


if __name__ == '__main__':
    main()
