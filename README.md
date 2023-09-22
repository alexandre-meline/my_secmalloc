# Projet my_secmalloc

Le projet **my_secmalloc** est une réimplémentation des fonctions de gestion de la mémoire telles que `malloc()`, `free()`, `calloc()`, et `realloc()`. Ces fonctions permettent d'allouer et de libérer de la mémoire de manière sécurisée en évitant les erreurs courantes comme les fuites de mémoire, les double-libérations ou les dépassements de tas.

## Compilation

Le projet peut être compilé en utilisant la commande `make`. Cela générera une bibliothèque partagée (`libmy_secmalloc.so`) et une bibliothèque statique (`libmy_secmalloc.a`).

## Utilisation

Pour utiliser les fonctions de gestion de la mémoire du projet, vous devez inclure le fichier d'en-tête `my_secmalloc.h` dans votre code source et lier votre programme à la bibliothèque `libmy_secmalloc`.

### Fonctions disponibles

- `my_malloc(size_t size)`: Alloue une zone de mémoire de la taille spécifiée et renvoie un pointeur vers le début de la zone allouée.
- `my_free(void *ptr)`: Libère la zone de mémoire pointée par le pointeur spécifié.
- `my_calloc(size_t nmemb, size_t size)`: Alloue une zone de mémoire contenant un tableau de `nmemb` éléments de taille `size`. La zone allouée est remplie de zéros.
- `my_realloc(void *ptr, size_t size)`: Réalloue une zone de mémoire précédemment allouée avec `my_malloc()`, `my_calloc()` ou `my_realloc()`. La nouvelle zone allouée a une taille de `size` octets.

### Exemple d'utilisation

```c
#include <stdio.h>
#include "my_secmalloc.h"

int main() {
    int *ptr = my_malloc(sizeof(int));
    *ptr = 42;
    printf("Valeur : %d\n", *ptr);
    my_free(ptr);
    return 0;
}
```

## Tests

Le projet inclut également des tests unitaires pour vérifier le bon fonctionnement des fonctions de gestion de la mémoire. Les tests sont écrits en utilisant la bibliothèque `criterion`. Pour exécuter les tests, utilisez la commande `make test`.

## Auteurs

Le projet my_secmalloc a été développé par [Alexandre Meline](https://www.linkedin.com/in/alexandre-m-020512234/) et [Thomas Devienne](https://www.linkedin.com/in/thomas-devienne/?originalSubdomain=fr).
