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

#include "hashindex.h"

typedef struct {
    char magic[8];
    int32_t num_entries;
    int32_t num_buckets;
    int8_t  key_size;
    int8_t  value_size;
} __attribute__((__packed__)) HashHeader;


#define MAGIC "DARCHASH"
#define EMPTY ((int32_t)-1)
#define DELETED ((int32_t)-2)
#define BUCKET_ADDR_READ(index, idx) (index->buckets + (idx * index->bucket_size))
#define BUCKET_ADDR_WRITE(index, idx) (index->buckets + (idx * index->bucket_size))

#define BUCKET_IS_DELETED(index, idx) (*((int32_t *)(BUCKET_ADDR_READ(index, idx) + index->key_size)) == DELETED)
#define BUCKET_IS_EMPTY(index, idx) (*((int32_t *)(BUCKET_ADDR_READ(index, idx) + index->key_size)) == EMPTY)

#define BUCKET_MATCHES_KEY(index, idx, key) (memcmp(key, BUCKET_ADDR_READ(index, idx), index->key_size) == 0)

#define BUCKET_MARK_DELETED(index, idx) (*((int32_t *)(BUCKET_ADDR_WRITE(index, idx) + index->key_size)) = DELETED)


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
            if (didx != -1) {
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

static void
hashindex_resize(HashIndex *index, int capacity)
{
    char *new_path = malloc(strlen(index->path) + 5);
    strcpy(new_path, index->path);
    strcat(new_path, ".tmp");
    HashIndex *new = hashindex_create(new_path, capacity, index->key_size, index->value_size);
    void *key = NULL;
    while((key = hashindex_next_key(index, key))) {
        hashindex_set(new, key, hashindex_get(index, key));
    }
    munmap(index->map_addr, index->map_length);
    index->map_addr = new->map_addr;
    index->map_length = new->map_length;
    index->num_buckets = new->num_buckets;
    index->limit = new->limit;
    index->buckets = new->buckets;
    unlink(index->path);
    rename(new_path, index->path);
    free(new_path);
    free(new->path);
    free(new);
}

/* Public API */
HashIndex *
hashindex_open(const char *path)
{
    int fd = open(path, O_RDWR);
    if(fd < 0) {
        fprintf(stderr, "Failed to open %s\n", path);
        return NULL;
    }
    off_t length = lseek(fd, 0, SEEK_END);
    void *addr = mmap(0, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if(addr == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap %s", path);
    }
    HashHeader *header = (HashHeader *)addr;
    HashIndex *index = malloc(sizeof(HashIndex));
    index->path = malloc(strlen(path) + 1);
    strcpy(index->path, path);
    index->map_addr = addr;
    index->map_length = length;
    index->num_entries = header->num_entries;
    index->num_buckets = header->num_buckets;
    index->key_size = header->key_size;
    index->value_size = header->value_size;
    index->bucket_size = index->key_size + index->value_size;
    index->buckets = (addr + sizeof(HashHeader));
    index->limit = (int)(index->num_buckets * .75);
    return index;
}

HashIndex *
hashindex_create(const char *path, int capacity, int key_size, int value_size)
{
    FILE *fd;
    int i;
    if(!(fd = fopen(path, "w"))) {
        fprintf(stderr, "Failed to create %s\n", path);
        return NULL;
    }
    HashHeader header;
    memcpy(header.magic, MAGIC, sizeof(MAGIC) - 1);
    header.num_entries = 0;
    header.num_buckets = capacity;
    header.key_size = key_size;
    header.value_size = value_size;
    int bucket_size = key_size + value_size;
    char *bucket = calloc(bucket_size, 1);
    if(fwrite(&header, 1, sizeof(header), fd) != sizeof(header))
        goto error;
    *((int32_t *)(bucket + key_size)) = EMPTY;
    for(i = 0; i < capacity; i++) {
        if(fwrite(bucket, 1, bucket_size, fd) != bucket_size)
            goto error;
    }
    free(bucket);
    fclose(fd);
    return hashindex_open(path);
error:
    fclose(fd);
    free(bucket);
    return NULL;
}

void
hashindex_clear(HashIndex *index)
{
    int i;
    for(i = 0; i < index->num_buckets; i++) {
        BUCKET_MARK_DELETED(index, i);
    }
    index->num_entries = 0;
    hashindex_resize(index, 16);
}

void
hashindex_flush(HashIndex *index)
{
    *((int32_t *)(index->map_addr + 8)) = index->num_entries;
    *((int32_t *)(index->map_addr + 12)) = index->num_buckets;
    msync(index->map_addr, index->map_length, MS_SYNC);
}

void
hashindex_close(HashIndex *index)
{
    hashindex_flush(index);
    munmap(index->map_addr, index->map_length);
    free(index->path);
    free(index);
}

const void *
hashindex_get(HashIndex *index, const void *key)
{
    int idx = hashindex_lookup(index, key);
    if(idx < 0) {
        return NULL;
    }
    return BUCKET_ADDR_READ(index, idx) + index->key_size;
}

void
hashindex_set(HashIndex *index, const void *key, const void *value)
{
    int idx = hashindex_lookup(index, key);
    uint8_t *ptr;
    if(idx < 0)
    {
        if(index->num_entries > index->limit) {
            hashindex_resize(index, index->num_buckets * 2);
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
}

void
hashindex_delete(HashIndex *index, const void *key)
{
    int idx = hashindex_lookup(index, key);
    if (idx < 0) {
        return;
    }
    BUCKET_MARK_DELETED(index, idx);
    index->num_entries -= 1;
}

void *
hashindex_next_key(HashIndex *index, const void *key)
{
    int idx = 0;
    if(key) {
        idx = 1 + (key - index->buckets) / index->bucket_size;
    }
    if (idx == index->num_buckets)
        return NULL;
    while(BUCKET_IS_EMPTY(index, idx) || BUCKET_IS_DELETED(index, idx)) {
        idx ++;
        if (idx == index->num_buckets)
            return NULL;
    }
    return BUCKET_ADDR_READ(index, idx);
}

int
hashindex_get_size(HashIndex *index)
{
    return index->num_entries;
}

