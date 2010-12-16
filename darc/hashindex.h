#ifndef __HASHINDEX_H__
#define __HASHINDEX_H__

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
    int limit;
} HashIndex;

HashIndex *hashindex_open(const char *path);
void hashindex_close(HashIndex *index);
void hashindex_flush(HashIndex *index);
HashIndex *hashindex_create(const char *path, int capacity, int key_size, int value_size);
const void *hashindex_get(HashIndex *index, const void *key);
void hashindex_set(HashIndex *index, const void *key, const void *value);
void hashindex_delete(HashIndex *index, const void *key);
void *hashindex_next_key(HashIndex *index, const void *key);
int hashindex_get_size(HashIndex *index);

#endif
