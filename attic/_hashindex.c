#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#if defined(__BYTE_ORDER)&&(__BYTE_ORDER == __BIG_ENDIAN)
#error This code is not big endian safe yet
#endif

typedef struct {
    char magic[8];
    int32_t num_entries;
    int32_t num_buckets;
    int8_t  key_size;
    int8_t  value_size;
} __attribute__((__packed__)) HashHeader;

typedef struct {
    char *path;
    void *map_addr;
    off_t map_length;
    void *buckets;
    int num_entries;
    int num_buckets;
    int key_size;
    int value_size;
    int bucket_size;
    int lower_limit;
    int upper_limit;
    int readonly;
} HashIndex;

#define MAGIC "ATTICIDX"
#define EMPTY ((int32_t)-1)
#define DELETED ((int32_t)-2)
#define MAX_BUCKET_SIZE 512
#define BUCKET_LOWER_LIMIT .25
#define BUCKET_UPPER_LIMIT .90
#define MIN_BUCKETS 1024
#define MAX(x, y) ((x) > (y) ? (x): (y))
#define BUCKET_ADDR_READ(index, idx) (index->buckets + (idx * index->bucket_size))
#define BUCKET_ADDR_WRITE(index, idx) (index->buckets + (idx * index->bucket_size))

#define BUCKET_IS_DELETED(index, idx) (*((int32_t *)(BUCKET_ADDR_READ(index, idx) + index->key_size)) == DELETED)
#define BUCKET_IS_EMPTY(index, idx) (*((int32_t *)(BUCKET_ADDR_READ(index, idx) + index->key_size)) == EMPTY)

#define BUCKET_MATCHES_KEY(index, idx, key) (memcmp(key, BUCKET_ADDR_READ(index, idx), index->key_size) == 0)

#define BUCKET_MARK_DELETED(index, idx) (*((int32_t *)(BUCKET_ADDR_WRITE(index, idx) + index->key_size)) = DELETED)

#define EPRINTF(msg, ...) EPRINTF_PATH(index->path, msg, ##__VA_ARGS__)
#define EPRINTF_PATH(path, msg, ...) fprintf(stderr, "hashindex: %s: " msg "\n", path, ##__VA_ARGS__)

static HashIndex *hashindex_open(const char *path, int readonly);
static int hashindex_close(HashIndex *index);
static int hashindex_clear(HashIndex *index);
static int hashindex_flush(HashIndex *index);
static HashIndex *hashindex_create(const char *path, int capacity, int key_size, int value_size);
static const void *hashindex_get(HashIndex *index, const void *key);
static int hashindex_set(HashIndex *index, const void *key, const void *value);
static int hashindex_delete(HashIndex *index, const void *key);
static void *hashindex_next_key(HashIndex *index, const void *key);


/* Private API */
static int
hashindex_index(HashIndex *index, const void *key)
{
    return *((uint32_t *)key) % index->num_buckets;
}

static int
hashindex_lookup(HashIndex *index, const void *key)
{
    int didx = -1;
    int start = hashindex_index(index, key);
    int idx = start;
    for(;;) {
        if(BUCKET_IS_EMPTY(index, idx))
        {
            return -1;
        }
        if(BUCKET_IS_DELETED(index, idx)) {
            if(didx == -1) {
                didx = idx;
            }
        }
        else if(BUCKET_MATCHES_KEY(index, idx, key)) {
            if (didx != -1 && !index->readonly) {
                memcpy(BUCKET_ADDR_WRITE(index, didx), BUCKET_ADDR_READ(index, idx), index->bucket_size);
                BUCKET_MARK_DELETED(index, idx);
                idx = didx;
            }
            return idx;
        }
        idx = (idx + 1) % index->num_buckets;
        if(idx == start) {
            return -1;
        }
    }
}

static int
hashindex_resize(HashIndex *index, int capacity)
{
    char *new_path = malloc(strlen(index->path) + 5);
    int ret = 0;
    strcpy(new_path, index->path);
    strcat(new_path, ".tmp");
    HashIndex *new;

    if(!(new = hashindex_create(new_path, capacity, index->key_size, index->value_size))) {
        free(new_path);
        return 0;
    }
    void *key = NULL;
    while((key = hashindex_next_key(index, key))) {
        hashindex_set(new, key, hashindex_get(index, key));
    }
    munmap(index->map_addr, index->map_length);
    index->map_addr = new->map_addr;
    index->map_length = new->map_length;
    index->num_buckets = new->num_buckets;
    index->lower_limit = new->lower_limit;
    index->upper_limit = new->upper_limit;
    index->buckets = new->buckets;
    if(unlink(index->path) < 0) {
        EPRINTF("unlink failed");
        goto out;
    }
    if(rename(new_path, index->path) < 0) {
        EPRINTF_PATH(new_path, "rename failed");
        goto out;
    }
    ret = 1;
out:
    free(new_path);
    free(new->path);
    free(new);
    return ret;
}

/* Public API */
static HashIndex *
hashindex_open(const char *path, int readonly)
{
    void *addr;
    int fd, oflags, prot;
    off_t length;
    HashHeader *header;
    HashIndex *index;

    if(readonly) {
        oflags = O_RDONLY;
        prot = PROT_READ;
    }
    else {
        oflags = O_RDWR;
        prot = PROT_READ | PROT_WRITE;
    }

    if((fd = open(path, oflags)) < 0) {
        EPRINTF_PATH(path, "open failed");
        fprintf(stderr, "Failed to open %s\n", path);
        return NULL;
    }
    if((length = lseek(fd, 0, SEEK_END)) < 0) {
        EPRINTF_PATH(path, "lseek failed");
        if(close(fd) < 0) {
            EPRINTF_PATH(path, "close failed");
        }
        return NULL;
    }
    addr = mmap(0, length, prot, MAP_SHARED, fd, 0);
    if(close(fd) < 0) {
        EPRINTF_PATH(path, "close failed");
        return NULL;
    }
    if(addr == MAP_FAILED) {
        EPRINTF_PATH(path, "mmap failed");
        return NULL;
    }
    header = (HashHeader *)addr;
    if(memcmp(header->magic, MAGIC, 8)) {
        EPRINTF_PATH(path, "Unknown file header");
        return NULL;
    }
    if(length != sizeof(HashHeader) + header->num_buckets * (header->key_size + header->value_size)) {
        EPRINTF_PATH(path, "Incorrect file length");
        return NULL;
    }
    if(!(index = malloc(sizeof(HashIndex)))) {
        EPRINTF_PATH(path, "malloc failed");
        return NULL;
    }
    index->readonly = readonly;
    index->map_addr = addr;
    index->map_length = length;
    index->num_entries = header->num_entries;
    index->num_buckets = header->num_buckets;
    index->key_size = header->key_size;
    index->value_size = header->value_size;
    index->bucket_size = index->key_size + index->value_size;
    index->buckets = (addr + sizeof(HashHeader));
    index->lower_limit = index->num_buckets > MIN_BUCKETS ? ((int)(index->num_buckets * BUCKET_LOWER_LIMIT)) : 0;
    index->upper_limit = (int)(index->num_buckets * BUCKET_UPPER_LIMIT);
    if(!(index->path = strdup(path))) {
        EPRINTF_PATH(path, "strdup failed");
        free(index);
        return NULL;
    }
    return index;
}

static HashIndex *
hashindex_create(const char *path, int capacity, int key_size, int value_size)
{
    FILE *fd;
    char bucket[MAX_BUCKET_SIZE] = {};
    int i, bucket_size;
    HashHeader header = {
        .magic = MAGIC, .num_entries = 0, .key_size = key_size, .value_size = value_size
    };
    capacity = MAX(MIN_BUCKETS, capacity);
    header.num_buckets = capacity;

    if(!(fd = fopen(path, "w"))) {
        EPRINTF_PATH(path, "fopen failed");
        return NULL;
    }
    bucket_size = key_size + value_size;
    if(fwrite(&header, 1, sizeof(header), fd) != sizeof(header)) {
        goto error;
    }
    *((int32_t *)(bucket + key_size)) = EMPTY;
    for(i = 0; i < capacity; i++) {
        if(fwrite(bucket, 1, bucket_size, fd) != bucket_size) {
            goto error;
        }
    }
    if(fclose(fd) < 0) {
        EPRINTF_PATH(path, "fclose failed");
        if(unlink(path) < 0) {
            EPRINTF_PATH(path, "unlink failed");
    }
        return NULL;
    }
    return hashindex_open(path, 0);
error:
    if(unlink(path) < 0) {
        EPRINTF_PATH(path, "unlink failed");
    }
    EPRINTF_PATH(path, "fwrite failed");
    if(fclose(fd) < 0) {
        EPRINTF_PATH(path, "fclose failed");
    }
    return NULL;
}

static int
hashindex_clear(HashIndex *index)
{
    int i;
    for(i = 0; i < index->num_buckets; i++) {
        BUCKET_MARK_DELETED(index, i);
    }
    index->num_entries = 0;
    return hashindex_resize(index, MIN_BUCKETS);
}

static int
hashindex_flush(HashIndex *index)
{
    if(index->readonly) {
        return 1;
    }
    *((int32_t *)(index->map_addr + 8)) = index->num_entries;
    *((int32_t *)(index->map_addr + 12)) = index->num_buckets;
    if(msync(index->map_addr, index->map_length, MS_SYNC) < 0) {
        EPRINTF("msync failed");
        return 0;
    }
    return 1;
}

static int
hashindex_close(HashIndex *index)
{
    int rv = 1;
    if(hashindex_flush(index) < 0) {
        rv = 0;
    }
    if(munmap(index->map_addr, index->map_length) < 0) {
        EPRINTF("munmap failed");
        rv = 0;
    }
    free(index->path);
    free(index);
    return rv;
}

static const void *
hashindex_get(HashIndex *index, const void *key)
{
    int idx = hashindex_lookup(index, key);
    if(idx < 0) {
        return NULL;
    }
    return BUCKET_ADDR_READ(index, idx) + index->key_size;
}

static int
hashindex_set(HashIndex *index, const void *key, const void *value)
{
    int idx = hashindex_lookup(index, key);
    uint8_t *ptr;
    if(idx < 0)
    {
        if(index->num_entries > index->upper_limit) {
            if(!hashindex_resize(index, index->num_buckets * 2)) {
                return 0;
            }
        }
        idx = hashindex_index(index, key);
        while(!BUCKET_IS_EMPTY(index, idx) && !BUCKET_IS_DELETED(index, idx)) {
            idx = (idx + 1) % index->num_buckets;
        }
        ptr = BUCKET_ADDR_WRITE(index, idx);
        memcpy(ptr, key, index->key_size);
        memcpy(ptr + index->key_size, value, index->value_size);
        index->num_entries += 1;
    }
    else
    {
        memcpy(BUCKET_ADDR_WRITE(index, idx) + index->key_size, value, index->value_size);
    }
    return 1;
}

static int
hashindex_delete(HashIndex *index, const void *key)
{
    int idx = hashindex_lookup(index, key);
    if (idx < 0) {
        return 1;
    }
    BUCKET_MARK_DELETED(index, idx);
    index->num_entries -= 1;
    if(index->num_entries < index->lower_limit) {
        if(!hashindex_resize(index, index->num_buckets / 2)) {
            return 0;
        }
    }
    return 1;
}

static void *
hashindex_next_key(HashIndex *index, const void *key)
{
    int idx = 0;
    if(key) {
        idx = 1 + (key - index->buckets) / index->bucket_size;
    }
    if (idx == index->num_buckets) {
        return NULL;
    }
    while(BUCKET_IS_EMPTY(index, idx) || BUCKET_IS_DELETED(index, idx)) {
        idx ++;
        if (idx == index->num_buckets) {
            return NULL;
        }
    }
    return BUCKET_ADDR_READ(index, idx);
}

static int
hashindex_get_size(HashIndex *index)
{
    return index->num_entries;
}

