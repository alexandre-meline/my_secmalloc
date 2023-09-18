#define _GNU_SOURCE

#include <sys/mman.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "my_secmalloc.h"
#include "my_secmalloc_private.h"

// variables globale
bool b_isused = false;
static StackMetadata st_metahead = NULL;
static void *p_ptr_datapool = NULL;
static size_t sz_page_size;
static size_t sz_meta_size;

/*
    Function that allows to display messages on the standard error output without using malloc.
*/
void my_log(const char *fmt, ...)
{
    va_list ap;
    char *c_buf;

    va_start(ap, fmt);
    size_t sz = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    c_buf = alloca(sz + 2);
    va_start(ap, fmt);
    vsnprintf(c_buf, sz + 2, fmt, ap);
    va_end(ap);

    write(2, c_buf, sz);
}

/*
    Function that checks for memory leaks.
*/
void check_memory_leaks()
{
    // we scan our metadata blocks and check that they are all released.
    // If not, an error is triggered and the program is stopped
    my_log("* Vérification des fuite de mémoire.\n");
    StackMetadata st_current_meta = st_metahead;
    while (st_current_meta != NULL)
    {
        if (st_current_meta->b_isfree == false)
        {
            my_log("*%s%s [ ERREUR ] Détection d'une fuite de mémoire (memory leak). Le block à l'adresse %p n'a pas été libéré correctement. Libération automatique de ce pointeur.%s%s\n", ANSI_COLOR_YELLOW, ANSI_STYLE_BOLD, st_current_meta->p_ptr_data, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
            my_free(st_current_meta->p_ptr_data);
        }
        st_current_meta = st_current_meta->p_next;
    }
    my_log("* Fin de la vérification des fuites de mémoire.\n");
}

/*
    A function that recovers a random value generated in the/dev/urandom file.
*/
unsigned int get_random_val()
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        my_log("*%s%s [ ERREUR ] Erreur lors de l'ouverture de /dev/urandom. Abandon !.%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
        return 1;
    }

    unsigned int ui64_random_val;
    if (lseek(fd, -4, SEEK_END) == -1) {
        my_log("*%s%s [ ERREUR ] Erreur lors de l'appel à lseek. Abandon !.%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
        return 1;
    }

    if (read(fd, &ui64_random_val, sizeof(ui64_random_val)) == -1) {
        my_log("*%s%s [ ERREUR ] Erreur lors de la lecture de /dev/urandom. Abandon !.%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
        return 1;
    }

    close(fd);

    return ui64_random_val;
}

/*
    We create our data and metadata pools.
*/
int init_my_malloc()
{
    int i64_nb_pages = 400;
    sz_page_size = getpagesize() * i64_nb_pages;
    sz_meta_size = META_SIZE * 1000000;

    // check memory leaks (memory blocks not released after running the program)
    atexit(check_memory_leaks);

    my_log("* Initialisation d'un pool de data et d'un pool de métadonnées.\n");

    // create a metadata pool
    my_log("* Creation du pool de data.\n");
    st_metahead = mmap(NULL, sz_meta_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st_metahead == MAP_FAILED)
    {
        my_log("*%s%s [ ERREUR ] Impossible de mapper le pool de metadonnées : code erreur %d%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET, errno);
        return 1;
    }
    my_log("* Pool de data crée à l'adresse %p\n", st_metahead);

    // we create our data pool
    my_log("* Creation du pool de metadonnées.\n");
    p_ptr_datapool = mmap(st_metahead, sz_page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p_ptr_datapool == MAP_FAILED)
    {
        my_log("*%s%s [ ERREUR ] Impossible de mapper le pool de données : code erreur %d%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET, errno);
        return 1;
    }
    my_log("* Pool de metadonnées crée à l'adresse %p\n", p_ptr_datapool);

    // we create our first metadata linked to the previously allocated memory space
    my_log("* Creation du premier élément de type metadonnées à l'adresse %p.\n", st_metahead);
    st_metahead->sz_size = sz_page_size;
    st_metahead->p_next = NULL;
    st_metahead->p_prev = NULL;
    st_metahead->b_isfree = true;
    st_metahead->p_ptr_data = p_ptr_datapool;
    st_metahead->i64_canari = 0;
    my_log("* Élément de type metadonnées crée avec les paramètres :\n"
        "*\t- adresse de la metadonnées: %p\n"
        "*\t- sz_size: %d\n"
        "*\t- p_next: %p\n"
        "*\t- p_prev: %p\n"
        "*\t- b_isfree: %s\n"
        "*\t- pointeur vers le block de données situé à l'adresse: %p\n"
        "*\t- i64_canari: %p\n", st_metahead, st_metahead->sz_size, st_metahead->p_next, st_metahead->p_prev, st_metahead->b_isfree ? "true" : "false", st_metahead->p_ptr_data, st_metahead->i64_canari
    );

    my_log("* Fin de l'initialisation d'un pool de data et d'un pool de métadonnées.\n");
    return 0;
}

/*
    A new block of metadata is created
    We consider st_new_current_meta as our new metadata block
    and st_data_left is the remaining unused memory space.
*/
int add_metadata_block(StackMetadata st_new_current_meta, int sz_size)
{
    StackMetadata st_data_left;

    my_log("* Réservation de l'espace mémoire situé à l'adresse %p dans le pool de données.\n", st_new_current_meta->p_ptr_data);

    my_log("* Creation d'un élément de type metadonnées à l'adresse %p représentant l'espace libre restant dans le data pool.\n", st_new_current_meta);
    st_data_left = st_new_current_meta + META_SIZE;
    my_log("* Adresse de la nouvelle metadonnée: %p (%p + %u).\n", st_data_left, st_new_current_meta, META_SIZE);
    st_data_left->sz_size = st_new_current_meta->sz_size - (sz_size + CANARI_SIZE);
    my_log("* Taille de la nouvelle metadonnée: %u (%u - (%u + %u)).\n", st_data_left->sz_size, st_new_current_meta->sz_size, sz_size, CANARI_SIZE);
    st_new_current_meta->sz_size = sz_size + CANARI_SIZE;
    my_log("* Taille de la metadonnée courante: %u (%u + %u).\n", st_data_left->sz_size, sz_size, CANARI_SIZE);
    st_data_left->p_ptr_data = st_new_current_meta->p_ptr_data + sz_size + CANARI_SIZE;
    my_log("* Adresse des données référencées par la nouvelle metadonnée: %p (%p + %u + %u)).\n", st_data_left->sz_size, st_new_current_meta->p_ptr_data, sz_size, CANARI_SIZE);
    st_data_left->b_isfree = true;
    st_new_current_meta->b_isfree = false;
    my_log("* Définition d'autres paramètres secondaires.\n");

    // we update the pointers of our metadata blocks
    st_data_left->p_next = st_new_current_meta->p_next;
    if (st_new_current_meta->p_next != NULL)
        st_new_current_meta->p_next->p_prev = st_data_left;
    st_new_current_meta->p_next = st_data_left;
    st_data_left->p_prev = st_new_current_meta;

    // we manage our canary
    st_new_current_meta->i64_canari = get_random_val();
    // if you want to perform a pwn challenge, uncomment the line bellow
    //st_new_current_meta->i64_canari = 0xcafebabe;

    my_log("* Écriture du i64_canari %p à l'adresse %p dans le pool de données.\n", st_new_current_meta->i64_canari, st_new_current_meta->p_ptr_data + st_new_current_meta->sz_size);
    *((int*)st_new_current_meta->p_ptr_data + st_new_current_meta->sz_size) = st_new_current_meta->i64_canari;

    my_log("* Élément de type metadonnées crée avec les paramètres :\n"
        "*\t- adresse de la metadonnées: %p\n"
        "*\t- sz_size: %d\n"
        "*\t- p_next: %p\n"
        "*\t- p_prev: %p\n"
        "*\t- b_isfree: %s\n"
        "*\t- pointeur vers le block de données situé à l'adresse: %p\n"
        "*\t- i64_canari: %p\n", st_new_current_meta, st_new_current_meta->sz_size, st_new_current_meta->p_next, st_new_current_meta->p_prev, st_new_current_meta->b_isfree ? "true" : "false", st_new_current_meta->p_ptr_data, st_new_current_meta->i64_canari
    );

    return 0;
}

/*
    Function to display the status of our chained list of metadata.
*/
void print_stack()
{
    my_log("\n~~~ Test de la liste chainee ~~~\n");
    StackMetadata m = st_metahead;
    while (m != NULL)
    {
        my_log("-\tblock @ %d of length %d\n", m->p_ptr_data, m->sz_size);
        m = m->p_next;
    }
    my_log("\n");
}

/*
    Implementation of secmalloc.
*/
void* my_malloc(size_t sz_size)
{
    bool b_isiterating;

    my_log("* Éxécution de la fonction my_malloc avec le paramètre :\n"
        "*\t- sz_size: %d\n", sz_size);

    my_log("* Vérification de la taille %d donnée en paramètre de la fonction my_malloc.\n", sz_size);

    // Check if the requested sz_size is valid
    if ((int) sz_size <= 0)
    {
        my_log("*%s%s [ ERREUR ]: Empty sz_size.%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
        return NULL;
    }
    my_log("* La taille %d passée en paramètre de la fonction est validée.\n", sz_size);

    // if our data pool and our metadata pool is not yet created, then we create it before using malloc
    if (b_isused == false)
    {
        int res = init_my_malloc();
        if (res != 0)
        {
            my_log("*%s%s [ ERREUR ] Une erreur s'est produite pendant l'initialisation du pool de données ou du pool de metadonnées : code erreur %d%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET, errno);
            exit(EXIT_FAILURE);
        }
        // we indicate that our data pool and our metadata pool are now created
        b_isused = true;
    }

    if (st_metahead == NULL)
    {
        my_log("*%s%s [ ERREUR ] Une erreur s'est produite pendant l'exécution (Impossible de lire les metadonnées) : code erreur %d%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET, errno);
        exit(EXIT_FAILURE);
    }

    // We are looking for a free metadata to allocate the new zone
    my_log("* Recherche un metadata libre pour y allouer la nouvelle zone.\n");
    StackMetadata st_current_meta = st_metahead;
    b_isiterating = true;
    size_t nb_blocks_meta = 0;
    while (b_isiterating == true)
    {
        nb_blocks_meta += 1;

        if (st_current_meta->b_isfree && st_current_meta->sz_size >= (sz_size + CANARI_SIZE))
        {
            my_log("* Le block %p référençant l'espace mémoire situé à l'adresse %p dans le pool de data est libre et dispose de %d octets disponibles.\n", st_current_meta, st_current_meta->p_ptr_data, st_current_meta->sz_size);

            // split memory if necessary
            if (st_current_meta->sz_size > (sz_size + CANARI_SIZE))
                add_metadata_block(st_current_meta, sz_size);

            // Return a pointer to the allocated area (after the metadata)
            my_log("* L'adresse %p est retournée à l'utilisateur.\n", st_current_meta->p_ptr_data);
            my_log("* Fin my_malloc.\n");
            return st_current_meta->p_ptr_data;
        }
        
        if (st_current_meta->p_next != NULL && st_current_meta->p_next != st_current_meta)
            st_current_meta = st_current_meta->p_next;
        else
            // if we have reached the end of our metadata list, we stop the loop
            b_isiterating = false;
    }

    my_log("* Aucun block anciennement crée n'a été trouvé.\n");

    // if our data pool is not large enough to access user data, we expand the pool
    my_log("* Vérification de la taille du pool de data.\n");
    if (st_current_meta->sz_size < sz_size)
    {
        // If we get here, it means there is not enough room in our data pool, then we expand it
        //size_t total_size = sz_size + META_SIZE;
        //size_t num_pages = (total_size + sz_page_size - 1) / sz_page_size;
        //size_t rounded_size = num_pages * sz_page_size;

        // if no block is available, then we must reallocate memory space to reserve the requested space
        //size_t new_datapool_len = sz_page_size - st_current_meta->sz_size + rounded_size;
        size_t new_datapool_len = sz_page_size + getpagesize();
        my_log("* Agrandissement du pool de data situé à l'adresse %p de %d octets à %d octets\n", p_ptr_datapool, sz_page_size, new_datapool_len);
        p_ptr_datapool = mremap(p_ptr_datapool, sz_page_size, new_datapool_len, MREMAP_FIXED);
        if (p_ptr_datapool == MAP_FAILED)
        {
            my_log("*%s%s [ ERREUR ] Impossible de remapper le pool de données : code erreur %d%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, errno, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
            return NULL;
        }

        // we update our global data pool sz_size
        sz_page_size = sz_page_size + new_datapool_len;

        my_log("* Fin de l'agrandissement du pool de data situé à l'adresse %p.\n", p_ptr_datapool);
    }

    // expand the metadata pool if it is too small to access a new entry
    my_log("* Vérification de la taille du pool de metadonnées.\n");
    if (nb_blocks_meta >= sz_meta_size)
    {
        my_log("* Agrandissement du pool de metadonnées situé à l'adresse %p de %d octets à %d octets", st_metahead, sz_meta_size, sz_meta_size + (sz_meta_size*1000));
        st_metahead = mremap(st_metahead, sz_meta_size, sz_meta_size + (sz_meta_size*1000), MREMAP_FIXED);
        if (st_metahead == MAP_FAILED)
        {
            my_log("*%s%s [ ERREUR ] Impossible de remapper le pool de données : code erreur %d%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, errno, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
            return NULL;
        }

        // update our new metadata pool sz_size
        sz_meta_size = sz_meta_size + (sz_meta_size * 1000);

        my_log("* Fin de l'agrandissement du pool de metadonnées situé à l'adresse %p.\n", st_metahead);
    }

    // we add a new element to our metadata list
    add_metadata_block(st_current_meta, sz_size);

    // Return a pointer to the allocated area (after the metadata)
    my_log("* L'adresse %p est retournée à l'utilisateur.\n", st_current_meta->p_ptr_data);
    my_log("* Fin my_malloc.\n");
    return st_current_meta->p_ptr_data;
}


void my_free(void* ptr) {

    my_log("* Éxécution de la fonction my_free avec le paramètre :\n"
        "*\t- ptr: %p\n", ptr);

    // Check if the given pointer is valid
    my_log("* Vérification de la validité du pointeur %p donné en paramètre.\n", ptr);
    if (ptr == NULL)
    {
        my_log("*%s%s [ ERREUR ]: Pointeur null (double free). Abandon !%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
        return;
    }
    my_log("* Pointeur validé.\n");

    // The metadata corresponding to the allocated memory space is retrieved (from the metadata sz_size)
    my_log("* Récupération de la metadonnée associée à la valeur du pointeur %p passé en paramètre.\n", ptr);
    StackMetadata st_current_meta = st_metahead;
    while (st_current_meta != NULL && st_current_meta->p_ptr_data != ptr)
        st_current_meta = st_current_meta->p_next;

    // check that the pointer given as a parameter corresponds to a descriptor in the meta-information pool
    my_log("* Vérification du fait que le pointeur %p donné en paramètre correspond bien à un descripteur dans le pool de meta-information.\n", ptr);
    if (st_current_meta == NULL)
    {
        my_log("*%s%s [ ERREUR ] Impossible de trouver l'adresse %p fournie à my_free dans la liste des métadonnées. Abandon !%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ptr, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
        exit(EXIT_FAILURE);
    }

    my_log("* La metadonnée associée à la valeur du pointeur %p passé en paramètre est :\n"
        "*\t- adresse de la metadonnées: %p\n"
        "*\t- sz_size: %d\n"
        "*\t- p_next: %p\n"
        "*\t- p_prev: %p\n"
        "*\t- b_isfree: %s\n"
        "*\t- pointeur vers le block de données situé à l'adresse: %p\n"
        "*\t- i64_canari: %p\n", st_current_meta, st_current_meta, st_current_meta->sz_size, st_current_meta->p_next, st_current_meta->p_prev, st_current_meta->b_isfree ? "true" : "false", st_current_meta->p_ptr_data, st_current_meta->i64_canari
    );

    // Check that the block is busy and if so, release it
    my_log("* Vérification de l'état du block sélectionné situé à l'adresse %p.\n", st_current_meta);
    if (st_current_meta->b_isfree == false)
        st_current_meta->b_isfree = true;
    // otherwise an error is displayed
    else
    {
        my_log("*%s%s [ ERREUR ] Le block de données est dèjà libre (double free). Abandon !%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET, errno);
        exit(EXIT_FAILURE);
    }
    my_log("* Le block est bien utilisé par un utilisateur et peux donc être correctement libéré.\n");

    // check that the canary has not been altered
    int *ptr_i64_canari = (int*)st_current_meta->p_ptr_data + st_current_meta->sz_size;
    int i64_canari = *ptr_i64_canari;
    my_log("* Récupération de la valeur du i64_canari à l'adresse %p : %p + %u = %p -> %p.\n", st_current_meta->p_ptr_data, st_current_meta->p_ptr_data, st_current_meta->sz_size, ptr_i64_canari, i64_canari);
    my_log("* Vérification de la valeur du i64_canari %p qui doit être égal à %p à l'adresse %p\n", st_current_meta->i64_canari, i64_canari, st_current_meta->p_ptr_data + st_current_meta->sz_size);
    if (st_current_meta->i64_canari != i64_canari)
    {
        my_log("*%s%s [ ERREUR ] Dépassement de tas détecté (heap overflow). Abandon !%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ANSI_COLOR_RESET, ANSI_STYLE_RESET);
        exit(EXIT_FAILURE);
    }
    my_log("* Le i64_canari %p correspond bien au i64_canari %p.\n", st_current_meta->i64_canari, i64_canari);

    // We check if the next st_current_meta is free, in which case we merge the two st_current_meta
    my_log("* Vérification que l'élément suivant notre metadonnée est libre dans le cadre d'une fusion des deux blocks.\n");
    if (st_current_meta->p_next != NULL && st_current_meta->p_next->b_isfree) {
        my_log("* Fusion des blocks situés aux adresses %p et %p.\n", st_current_meta, st_current_meta->p_next);

        // We update the prev and next pointers of the st_current_meta concerned
        st_current_meta->sz_size += st_current_meta->p_next->sz_size;
        st_current_meta->p_next = st_current_meta->p_next->p_next;
        if (st_current_meta->p_next != NULL) {
            st_current_meta->p_next->p_prev = st_current_meta;
        }
        my_log("* Etat du nouveau block à l'adresse %p :\n"
            "*\t- adresse de la metadonnées: %p\n"
            "*\t- sz_size: %d\n"
            "*\t- p_next: %p\n"
            "*\t- p_prev: %p\n"
            "*\t- b_isfree: %s\n"
            "*\t- pointeur vers le block de données situé à l'adresse: %p\n"
            "*\t- i64_canari: %p\n", st_current_meta, st_current_meta, st_current_meta->sz_size, st_current_meta->p_next, st_current_meta->p_prev, st_current_meta->b_isfree ? "true" : "false", st_current_meta->p_ptr_data, st_current_meta->i64_canari
        );

        my_log("* Fusion correctement opérée.\n");
    }
    else
        my_log("* Aucune fusion possible dans la configuration actuelle.\n");

    // We check if the previous st_current_meta is free, in which case we merge the two st_current_meta
    my_log("* Vérification que l'élément précédent notre metadonnée est libre dans le cadre d'une fusion des deux blocks.\n");
    if (st_current_meta->p_prev != NULL && st_current_meta->p_prev->b_isfree) {
        my_log("* Fusion des blocks situés aux adresses %p et %p.\n", st_current_meta, st_current_meta->p_prev);
        
        // We update the prev and next pointers of the st_current_meta concerned
        st_current_meta->p_prev->sz_size += st_current_meta->sz_size;
        st_current_meta->p_prev->p_next = st_current_meta->p_next;
        if (st_current_meta->p_next != NULL) {
            st_current_meta->p_next->p_prev = st_current_meta->p_prev;
        }
        my_log("* Etat du nouveau block à l'adresse %p :\n"
            "*\t- adresse de la metadonnées: %p\n"
            "*\t- sz_size: %d\n"
            "*\t- p_next: %p\n"
            "*\t- p_prev: %p\n"
            "*\t- b_isfree: %s\n"
            "*\t- pointeur vers le block de données situé à l'adresse: %p\n"
            "*\t- i64_canari: %p\n", st_current_meta, st_current_meta, st_current_meta->sz_size, st_current_meta->p_next, st_current_meta->p_prev, st_current_meta->b_isfree ? "true" : "false", st_current_meta->p_ptr_data, st_current_meta->i64_canari
        );

        my_log("* Fusion correctement opérée.\n");
    }
    else
        my_log("* Aucune fusion possible dans la configuration actuelle.\n");
    my_log("* Fin my_free.\n");
}

/*
    Implementation of seccalloc.
*/
void *my_calloc(size_t sz_nmemb, size_t sz_size)
{
    my_log("* Éxécution de la fonction my_calloc avec les paramètres :\n"
        "*\t- sz_nmemb: %d\n"
        "*\t- sz_size: %d\n", sz_nmemb, sz_size);

    my_log("* %d allocations mémoire réalisées à l'aide de my_malloc, chaque allocations étant d'une taille de %d.\n", sz_nmemb, sz_size);
    size_t i;
    size_t total_size = sz_nmemb * sz_size;
    void* p_ptr = my_malloc(total_size);
    if (p_ptr != NULL)
    {
        my_log("* Initialisation du block mémoire situé à l'adresse %p du tableau avec des 0.\n", p_ptr);           
        char* byte_ptr = (char*) p_ptr;           
        for (i = 0; i < sz_size; i++)
            byte_ptr[i] = 0;
    }

    my_log("* L'adresse %p est retournée à l'utilisateur.\n", p_ptr);
    my_log("* Fin my_calloc.\n");
    return p_ptr;
}

/*
    Implementation of secrealloc.
*/
void *my_realloc(void *ptr, size_t sz_size)
{

    my_log("* Éxécution de la fonction my_realloc avec les paramètres :\n"
        "*\t- ptr: %p\n"
        "*\t- sz_size: %d\n", ptr, sz_size);

    void *p_new_ptr = NULL;

    my_log("* Vérification de la validité du pointeur %p passé en paramètre.\n", ptr);
    if(ptr == NULL)
    {
        my_log("* Pointeur null détecté (%p).\n");
        my_log("* Allocation mémoire réalisée à l'aide de my_malloc d'une taille de %d.\n", sz_size);
        p_new_ptr = my_malloc(sz_size);
        if (p_new_ptr == NULL)
            return NULL;

        my_log("* L'adresse %p est retournée à l'utilisateur.\n", p_new_ptr);
        return p_new_ptr;
    }
    else if(sz_size == 0)
    {
        my_log("* La taille précisée est égale à 0.\n");
        my_log("* Le pointeur passé en paramètre est libéré.\n");
        my_free(ptr);
        return NULL;
    }

    // search for the metadata associated with this pointer
    my_log("* Recherche de la métadonnée associée à l'adresse %p.\n", ptr);
    StackMetadata metadata = st_metahead;
    while (metadata != NULL && metadata->p_ptr_data != ptr)
        metadata = metadata->p_next;

    // check that the pointer passed as a parameter is valid
    my_log("* Vérification de la métadonnée associée à l'adresse %p.\n", ptr);
    if (metadata == NULL)
    {
        my_log("*%s%s [ ERREUR ] Pointeur invalide détecté: le pointeur %p passé en paramètre de la fonction my_realloc ne correspond pas à une valeur de pointeur dans les metadonnées. Abandon !%s%s\n", ANSI_COLOR_RED, ANSI_STYLE_BOLD, ptr, ANSI_STYLE_RESET, ANSI_COLOR_RESET);
        return NULL;
    }

    my_log("* Le pointeur %p et la taille %d passé en paramètre sont validés.\n", ptr, sz_size);
    my_log("* Allocation mémoire réalisée à l'aide de my_malloc d'une taille de %d.\n", sz_size);
    p_new_ptr = my_malloc(sz_size);
    if(p_new_ptr == NULL) 
    {
        my_free(ptr);
        return NULL;
    }

    // Copy old data from old address to new address
    my_log("* Copie des données située à l'adresse %p vers l'adresse %p.\n", ptr, p_new_ptr);
    char *data = (char*) metadata->p_ptr_data;
    char *new_data = (char*) p_new_ptr;
    memcpy(new_data, data, metadata->sz_size);

    // We free the memory located at the old address
    my_log("* Libération de la mémoire située à l'adresse %p.\n", ptr);
    my_free(ptr);
    
    my_log("* L'adresse %p est retournée à l'utilisateur.\n", p_new_ptr);
    my_log("* Fin my_realloc.\n");
    return p_new_ptr;
}

#ifdef DYNAMIC
/*
 * When the library is compiled into . so the malloc/free/calloc/realloc symbols will be visible
 * */

void *malloc(size_t sz_size)
{
    return my_malloc(sz_size);
}
void free(void *ptr)
{
    my_free(ptr);
}
void *calloc(size_t sz_nmemb, size_t sz_size)
{
    return my_calloc(sz_nmemb, sz_size);
}

void *realloc(void *ptr, size_t sz_size)
{
    return my_realloc(ptr, sz_size);
}

#endif
