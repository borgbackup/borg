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

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define BARREL_SHIFT(v, shift) ( ((v) << (shift)) | ((v) >> ((32 - (shift)) & 0x1f)) )

static uint32_t
c_buzhash_start(const uint8_t *data, size_t len, const uint32_t *h)
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
c_buzhash_update(uint32_t sum, uint8_t remove, uint8_t add, size_t len, const uint32_t *h)
{
    uint32_t lenmod = len & 0x1f;  /* Note: replace by constant to get small speedup */
    return BARREL_SHIFT(sum, 1) ^ BARREL_SHIFT(h[remove], lenmod) ^ h[add];
}

static uint32_t
c_buzhash_find(const uint8_t *data, size_t len, size_t min_size, size_t max_size,
               size_t window_size, uint32_t chunk_mask, const uint32_t *h)
{
    // find a single cutting position that meets the criteria to cut a chunk with
    // min_size <= len(chunk) <= max_size.
    int found;
    uint32_t sum;
    size_t position; // index of potential cutting position, start of buzhash window
    uint8_t *p;  // pointer corresponding to position in data
    uint8_t *stop_at;
    size_t addtl_size;
    if (len < min_size + window_size) {
        return 0xffffffff;  // need more data!
    }
    position = min_size;
    p = (uint8_t *) data + position;
    sum = c_buzhash_start(p, window_size, h);
    found = (sum & chunk_mask) == 0;
    if(!found) {
        // process up to what we have, but dot not exceed max_size
        addtl_size = MIN(len - min_size - window_size, max_size - min_size);
        stop_at = p + addtl_size;
        while (!found && p < stop_at) {
            // new window is now from p+1 .. p+window_size,
            // *p is the byte removed, *(p + window_size) is the byte added.
            sum = c_buzhash_update(sum, *p, *(p + window_size), window_size, h);
            p++;  // NOW p points to the new window start
            found = (sum & chunk_mask) == 0;
        }
        position = p - data;
    }
    if (found || position == max_size)
        return position;
    else
        return 0xffffffff;  // need more data!
}
