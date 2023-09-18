#ifndef _SECMALLOC_H
#define _SECMALLOC_H

#include <stdlib.h>

#if DYNAMIC
void    *malloc(size_t size);
void    free(void *ptr);
void    *calloc(size_t nmemb, size_t size);
void    *realloc(void *ptr, size_t size);
// when compiling the . so the my_ functions become private
#define MY static
#else
// for tests, the my_ functions are public
#define MY
#endif

MY void    *my_malloc(size_t size);
MY void    my_free(void *ptr);
MY void    *my_calloc(size_t nmemb, size_t size);
MY void    *my_realloc(void *ptr, size_t size);

#endif
