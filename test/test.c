#include <criterion/criterion.h>
#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include "my_secmalloc.h"
#include "my_secmalloc_private.h"

Test(mmap, simple) {
    printf("=== TEST DE MMAP ET MUNMAP ===\n");
    printf("Ici on fait un test simple de mmap\n");
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    cr_expect(ptr != NULL);
    int res = munmap(ptr, 4096);
    cr_expect(res == 0);
    char *str = my_malloc(15);
    strncpy(str, "ca marche", 15);
    printf("bla %s\n", str);
    printf("=== FIN DE MMAP ET MUNMAP ===\n\n");
}

Test(malloc, free)
{
    printf("=== TEST DE MALLOC ET FREE ===\n");
    char *ptr = my_malloc(17);
    strncpy(ptr, "Ca marche baby :)", 18);
    printf("\nBla -- %s\n", ptr);
    printf("Adresse de ptr : %p\n", ptr);
    my_free(ptr);
    printf("=== FIN DE MALLOC ET FREE ===\n\n");
}

Test(malloc, multiple_free)
{
    printf("=== TEST DE MALLOC ET MULTIPLE FREE ===\n");
    char *str1 = my_malloc(3000);
    char *str2 = my_malloc(17);
    char *str3 = my_malloc(17);

    strncpy(str1, "Ca marche baby 1", 17);
    strncpy(str2, "Ca marche baby 2", 22);
    strncpy(str3, "Ca marche baby 3", 17);

    printf("Bla -- %s\n", str1);
    printf("Bla -- %s\n", str2);
    printf("Bla -- %s\n", str3);

    printf("Adresse de str1 : %p\n", str1);
    printf("Adresse de str2 : %p\n", str2);
    printf("Adresse de str3 : %p\n", str3);

    my_free(str1);
    my_free(str2);
    my_free(str3);

    char *str4 = my_malloc(30);
    printf("Adresse de str4 : %p\n", str4);
    my_free(str4);

    printf("=== FIN DE MALLOC ET MULTIPLE FREE ===\n\n");
}

Test(malloc, calloc)
{
    printf("\n=== TEST DE CALLOC ===\n");
    int *tab1 = my_calloc(10, sizeof(int));
    printf("Calloc ==> %p", tab1);
    printf("\n=== FIN DE TEST DE CALLOC ===\n");

}

Test(realloc, simple)
{
    char *ptr = my_malloc(15);
    cr_expect(ptr != NULL);
    printf("\n=== TEST REALLOC ===\n");
    char *rea = my_realloc(ptr, 30);
    cr_expect(rea != NULL);
    printf("Pointeur : %p --> %p", ptr, rea);
    my_free(rea);
    printf("\n=== FIN DE TEST DE REALLOC ===\n");
}

Test(metadata, resize)
{
    printf("\n=== TEST DU RESIZE DE METADATA ===\n");
    char *a;

    for (int i=0 ; i<10000 ; i+=1)
    {
        a = my_malloc(1);
        printf("%d: Nouvelle adresse de a: %p\n", i, a);
    }

    // on resize le metadata pool
    a = my_malloc(1);
    my_free(a);
    printf("=== FIN TEST ===\n");
}

Test(datapool, resize)
{
    printf("\n=== TEST DU RESIZE DE DATAPOOL ===\n");
    char *a, *b;

    a = my_malloc(1638300);
    b = my_malloc(200);

    my_free(a);
    my_free(b);
    printf("=== FIN TEST ===\n");
}

Test(calloc, calloc_et_free)
{
    printf("\n=== TEST DU CALLOC ET DU FREE CALLOC ===\n");
    char *ptr = my_calloc(10, sizeof(int));
    cr_expect(ptr != NULL);
    my_free(ptr);
    cr_expect(ptr == NULL);
    printf("=== FIN TEST ===\n");
}

Test(erreur_1, malloc)
{
    printf("\n=== TEST DES ERREUR DE SIZE INVALIDES POUR MALLOC ===\n");
    char* ptr_1 = my_malloc(0);
    cr_expect(ptr_1 == NULL);
    char* ptr_2 = my_malloc(-10);
    cr_expect(ptr_2 == NULL);
    char* ptr_3 = my_malloc(10);
    cr_expect(ptr_3 != NULL);
    my_free(ptr_3);
    printf("=== FIN TEST ===\n");
}

// =============================================
// Ces test génèrent une erreur volontairement
// =============================================

Test(erreur_2, heap_overflow)
{
    printf("\n=== TEST : HEAP OVERFLOW ===\n");
    char *ptr = my_malloc(6);
    cr_expect(ptr != NULL);
    printf("On essaye de provoquer un buffer overflow.\n");
    strncpy(ptr, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca", 45);
    my_free(ptr);
    printf("=== FIN TEST ===\n");
}

Test(erreur_3, memory_leak)
{
    printf("\n=== TEST : MEMORY LEAK ===\n");
    char *ptr = my_malloc(15);
    cr_expect(ptr != NULL);
    printf("=== FIN TEST ===\n");
}

Test(erreur_4, double_free)
{
    printf("\n=== TEST : DOUBLE FREE ===\n");
    char *ptr = my_malloc(15);
    cr_expect(ptr != NULL);
    my_free(ptr);
    my_free(ptr);
    printf("=== FIN TEST ===\n");
}
