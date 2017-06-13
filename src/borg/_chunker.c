#include <Python.h>
#include <fcntl.h>

/* Cyclic polynomial / buzhash

https://en.wikipedia.org/wiki/Rolling_hash

http://www.serve.net/buz/Notes.1st.year/HTML/C6/rand.012.html (by "BUZ", the inventor)

http://www.dcs.gla.ac.uk/~hamer/cakes-talk.pdf (see buzhash slide)

Some properties of buzhash / of this implementation:

(1) the hash is designed for inputs <= 32 bytes, but the chunker uses it on a 4095 byte window;
    any repeating bytes at distance 32 within those 4095 bytes can cause cancellation within
    the hash function, e.g. in "X <any 31 bytes> X", the last X would cancel out the influence
    of the first X on the hash value.

(2) the hash table is supposed to have (according to the BUZ) exactly a 50% distribution of
    0/1 bit values per position, but the hard coded table below doesn't fit that property.

(3) if you would use a window size divisible by 64, the seed would cancel itself out completely.
    this is why we use a window size of 4095 bytes.

Another quirk is that, even with the 4095 byte window, XORing the entire table by a constant
is equivalent to XORing the hash output with a different constant. but since the seed is stored
encrypted, i think it still serves its purpose.
*/

static uint32_t table_base[] =
{
    0xe7f831ec, 0xf4026465, 0xafb50cae, 0x6d553c7a, 0xd639efe3, 0x19a7b895, 0x9aba5b21, 0x5417d6d4,
    0x35fd2b84, 0xd1f6a159, 0x3f8e323f, 0xb419551c, 0xf444cebf, 0x21dc3b80, 0xde8d1e36, 0x84a32436,
    0xbeb35a9d, 0xa36f24aa, 0xa4e60186, 0x98d18ffe, 0x3f042f9e, 0xdb228bcd, 0x096474b7, 0x5c20c2f7,
    0xf9eec872, 0xe8625275, 0xb9d38f80, 0xd48eb716, 0x22a950b4, 0x3cbaaeaa, 0xc37cddd3, 0x8fea6f6a,
    0x1d55d526, 0x7fd6d3b3, 0xdaa072ee, 0x4345ac40, 0xa077c642, 0x8f2bd45b, 0x28509110, 0x55557613,
    0xffc17311, 0xd961ffef, 0xe532c287, 0xaab95937, 0x46d38365, 0xb065c703, 0xf2d91d0f, 0x92cd4bb0,
    0x4007c712, 0xf35509dd, 0x505b2f69, 0x557ead81, 0x310f4563, 0xbddc5be8, 0x9760f38c, 0x701e0205,
    0x00157244, 0x14912826, 0xdc4ca32b, 0x67b196de, 0x5db292e8, 0x8c1b406b, 0x01f34075, 0xfa2520f7,
    0x73bc37ab, 0x1e18bc30, 0xfe2c6cb3, 0x20c522d0, 0x5639e3db, 0x942bda35, 0x899af9d1, 0xced44035,
    0x98cc025b, 0x255f5771, 0x70fefa24, 0xe928fa4d, 0x2c030405, 0xb9325590, 0x20cb63bd, 0xa166305d,
    0x80e52c0a, 0xa8fafe2f, 0x1ad13f7d, 0xcfaf3685, 0x6c83a199, 0x7d26718a, 0xde5dfcd9, 0x79cf7355,
    0x8979d7fb, 0xebf8c55e, 0xebe408e4, 0xcd2affba, 0xe483be6e, 0xe239d6de, 0x5dc1e9e0, 0x0473931f,
    0x851b097c, 0xac5db249, 0x09c0f9f2, 0xd8d2f134, 0xe6f38e41, 0xb1c71bf1, 0x52b6e4db, 0x07224424,
    0x6cf73e85, 0x4f25d89c, 0x782a7d74, 0x10a68dcd, 0x3a868189, 0xd570d2dc, 0x69630745, 0x9542ed86,
    0x331cd6b2, 0xa84b5b28, 0x07879c9d, 0x38372f64, 0x7185db11, 0x25ba7c83, 0x01061523, 0xe6792f9f,
    0xe5df07d1, 0x4321b47f, 0x7d2469d8, 0x1a3a4f90, 0x48be29a3, 0x669071af, 0x8ec8dd31, 0x0810bfbf,
    0x813a06b4, 0x68538345, 0x65865ddc, 0x43a71b8e, 0x78619a56, 0x5a34451d, 0x5bdaa3ed, 0x71edc7e9,
    0x17ac9a20, 0x78d10bfa, 0x6c1e7f35, 0xd51839d9, 0x240cbc51, 0x33513cc1, 0xd2b4f795, 0xccaa8186,
    0x0babe682, 0xa33cf164, 0x18c643ea, 0xc1ca105f, 0x9959147a, 0x6d3d94de, 0x0b654fbe, 0xed902ca0,
    0x7d835cb5, 0x99ba1509, 0x6445c922, 0x495e76c2, 0xf07194bc, 0xa1631d7e, 0x677076a5, 0x89fffe35,
    0x1a49bcf3, 0x8e6c948a, 0x0144c917, 0x8d93aea1, 0x16f87ddf, 0xc8f25d49, 0x1fb11297, 0x27e750cd,
    0x2f422da1, 0xdee89a77, 0x1534c643, 0x457b7b8b, 0xaf172f7a, 0x6b9b09d6, 0x33573f7f, 0xf14e15c4,
    0x526467d5, 0xaf488241, 0x87c3ee0d, 0x33be490c, 0x95aa6e52, 0x43ec242e, 0xd77de99b, 0xd018334f,
    0x5b78d407, 0x498eb66b, 0xb1279fa8, 0xb38b0ea6, 0x90718376, 0xe325dee2, 0x8e2f2cba, 0xcaa5bdec,
    0x9d652c56, 0xad68f5cb, 0xa77591af, 0x88e37ee8, 0xf8faa221, 0xfcbbbe47, 0x4f407786, 0xaf393889,
    0xf444a1d9, 0x15ae1a2f, 0x40aa7097, 0x6f9486ac, 0x29d232a3, 0xe47609e9, 0xe8b631ff, 0xba8565f4,
    0x11288749, 0x46c9a838, 0xeb1b7cd8, 0xf516bbb1, 0xfb74fda0, 0x010996e6, 0x4c994653, 0x1d889512,
    0x53dcd9a3, 0xdd074697, 0x1e78e17c, 0x637c98bf, 0x930bb219, 0xcf7f75b0, 0xcb9355fb, 0x9e623009,
    0xe466d82c, 0x28f968d3, 0xfeb385d9, 0x238e026c, 0xb8ed0560, 0x0c6a027a, 0x3d6fec4b, 0xbb4b2ec2,
    0xe715031c, 0xeded011d, 0xcdc4d3b9, 0xc456fc96, 0xdd0eea20, 0xb3df8ec9, 0x12351993, 0xd9cbb01c,
    0x603147a2, 0xcf37d17d, 0xf7fcd9dc, 0xd8556fa3, 0x104c8131, 0x13152774, 0xb4715811, 0x6a72c2c9,
    0xc5ae37bb, 0xa76ce12a, 0x8150d8f3, 0x2ec29218, 0xa35f0984, 0x48c0647e, 0x0b5ff98c, 0x71893f7b
};

#define BARREL_SHIFT(v, shift) ( ((v) << shift) | ((v) >> ((32 - shift) & 0x1f)) )

size_t pagemask;

static uint32_t *
buzhash_init_table(uint32_t seed)
{
    int i;
    uint32_t *table = malloc(1024);
    for(i = 0; i < 256; i++)
    {
        table[i] = table_base[i] ^ seed;
    }
    return table;
}

static uint32_t
buzhash(const unsigned char *data, size_t len, const uint32_t *h)
{
    uint32_t i;
    uint32_t sum = 0, imod;
    for(i = len - 1; i > 0; i--)
    {
        imod = i & 0x1f;
        sum ^= BARREL_SHIFT(h[*data], imod);
        data++;
    }
    return sum ^ h[*data];
}

static uint32_t
buzhash_update(uint32_t sum, unsigned char remove, unsigned char add, size_t len, const uint32_t *h)
{
    uint32_t lenmod = len & 0x1f;  /* Note: replace by constant to get small speedup */
    return BARREL_SHIFT(sum, 1) ^ BARREL_SHIFT(h[remove], lenmod) ^ h[add];
}

typedef struct {
    uint32_t chunk_mask;
    uint32_t *table;
    uint8_t *data;
    PyObject *fd;
    int fh;
    int done, eof;
    size_t min_size, buf_size, window_size, remaining, position, last;
    off_t bytes_read, bytes_yielded;
} Chunker;

static Chunker *
chunker_init(size_t window_size, uint32_t chunk_mask, size_t min_size, size_t max_size, uint32_t seed)
{
    Chunker *c = calloc(sizeof(Chunker), 1);
    c->window_size = window_size;
    c->chunk_mask = chunk_mask;
    c->min_size = min_size;
    c->table = buzhash_init_table(seed);
    c->buf_size = max_size;
    c->data = malloc(c->buf_size);
    c->fh = -1;
    return c;
}

static void
chunker_set_fd(Chunker *c, PyObject *fd, int fh)
{
    Py_XDECREF(c->fd);
    c->fd = fd;
    Py_INCREF(fd);
    c->fh = fh;
    c->done = 0;
    c->remaining = 0;
    c->bytes_read = 0;
    c->bytes_yielded = 0;
    c->position = 0;
    c->last = 0;
    c->eof = 0;
}

static void
chunker_free(Chunker *c)
{
    Py_XDECREF(c->fd);
    free(c->table);
    free(c->data);
    free(c);
}

static int
chunker_fill(Chunker *c)
{
    ssize_t n;
    off_t offset, length;
    int overshoot;
    PyObject *data;
    memmove(c->data, c->data + c->last, c->position + c->remaining - c->last);
    c->position -= c->last;
    c->last = 0;
    n = c->buf_size - c->position - c->remaining;
    if(c->eof || n == 0) {
        return 1;
    }
    if(c->fh >= 0) {
        offset = c->bytes_read;
        // if we have a os-level file descriptor, use os-level API
        n = read(c->fh, c->data + c->position + c->remaining, n);
        if(n > 0) {
            c->remaining += n;
            c->bytes_read += n;
        }
        else
        if(n == 0) {
            c->eof = 1;
        }
        else {
            // some error happened
            PyErr_SetFromErrno(PyExc_OSError);
            return 0;
        }
        length = c->bytes_read - offset;
        #if ( ( _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L ) && defined(POSIX_FADV_DONTNEED) )

        // Only do it once per run.
        if (pagemask == 0)
            pagemask = getpagesize() - 1;

        // We tell the OS that we do not need the data that we just have read any
        // more (that it maybe has in the cache). This avoids that we spoil the
        // complete cache with data that we only read once and (due to cache
        // size limit) kick out data from the cache that might be still useful
        // for the OS or other processes.
        // We rollback the initial offset back to the start of the page,
        // to avoid it not being truncated as a partial page request.
        if (length > 0) {
            // All Linux kernels (at least up to and including 4.6(.0)) have a bug where
            // they truncate last partial page of POSIX_FADV_DONTNEED request, so we need
            // to page-align it ourselves. We'll need the rest of this page on the next
            // read (assuming this was not EOF).
            overshoot = (offset + length) & pagemask;
        } else {
            // For length == 0 we set overshoot 0, so the below
            // length - overshoot is 0, which means till end of file for
            // fadvise. This will cancel the final page and is not part
            // of the above workaround.
            overshoot = 0;
        }

        posix_fadvise(c->fh, offset & ~pagemask, length - overshoot, POSIX_FADV_DONTNEED);
        #endif
    }
    else {
        // no os-level file descriptor, use Python file object API
        data = PyObject_CallMethod(c->fd, "read", "i", n);
        if(!data) {
            return 0;
        }
        n = PyBytes_Size(data);
        if(PyErr_Occurred()) {
            // we wanted bytes(), but got something else
            return 0;
        }
        if(n) {
            memcpy(c->data + c->position + c->remaining, PyBytes_AsString(data), n);
            c->remaining += n;
            c->bytes_read += n;
        }
        else {
            c->eof = 1;
        }
        Py_DECREF(data);
    }
    return 1;
}

static PyObject *
chunker_process(Chunker *c)
{
    uint32_t sum, chunk_mask = c->chunk_mask;
    size_t n = 0, old_last, min_size = c->min_size, window_size = c->window_size;

    if(c->done) {
        if(c->bytes_read == c->bytes_yielded)
            PyErr_SetNone(PyExc_StopIteration);
        else
            PyErr_SetString(PyExc_Exception, "chunkifier byte count mismatch");
        return NULL;
    }
    while(c->remaining < min_size + window_size + 1 && !c->eof) {  /* see assert in Chunker init */
        if(!chunker_fill(c)) {
            return NULL;
        }
    }
    /* here we either are at eof ... */
    if(c->eof) {
        c->done = 1;
        if(c->remaining) {
            c->bytes_yielded += c->remaining;
            return PyMemoryView_FromMemory((char *)(c->data + c->position), c->remaining, PyBUF_READ);
        }
        else {
            if(c->bytes_read == c->bytes_yielded)
                PyErr_SetNone(PyExc_StopIteration);
            else
                PyErr_SetString(PyExc_Exception, "chunkifier byte count mismatch");
            return NULL;
        }
    }
    /* ... or we have at least min_size + window_size + 1 bytes remaining.
     * We do not want to "cut" a chunk smaller than min_size and the hash
     * window starts at the potential cutting place.
     */
    c->position += min_size;
    c->remaining -= min_size;
    n += min_size;
    sum = buzhash(c->data + c->position, window_size, c->table);
    while(c->remaining > c->window_size && (sum & chunk_mask)) {
        sum = buzhash_update(sum, c->data[c->position],
                             c->data[c->position + window_size],
                             window_size, c->table);
        c->position++;
        c->remaining--;
        n++;
        if(c->remaining <= window_size) {
            if(!chunker_fill(c)) {
                return NULL;
            }
        }
    }
    if(c->remaining <= window_size) {
        c->position += c->remaining;
        c->remaining = 0;
    }
    old_last = c->last;
    c->last = c->position;
    n = c->last - old_last;
    c->bytes_yielded += n;
    return PyMemoryView_FromMemory((char *)(c->data + old_last), n, PyBUF_READ);
}
