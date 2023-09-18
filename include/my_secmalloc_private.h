#ifndef _SECMALLOC_PRIVATE_H
#define _SECMALLOC_PRIVATE_H
#define META_SIZE sizeof(struct Stack_metadata)
#define CANARI_SIZE sizeof(int)

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_STYLE_BOLD    "\033[1m"
#define ANSI_STYLE_RESET   "\033[0m"

// Struct pour les metadata
typedef struct Stack_metadata {
    size_t sz_size;
    struct Stack_metadata *p_prev;
    struct Stack_metadata *p_next;
    bool b_isfree;
    void *p_ptr_data;
    int i64_canari;
}Stack_metadata, *StackMetadata;

void my_log(const char *fmt, ...);
int init_my_malloc();
int add_metadata_block(StackMetadata current_metadata, int size);
void check_memory_leaks();
unsigned int get_random_val();

#endif
