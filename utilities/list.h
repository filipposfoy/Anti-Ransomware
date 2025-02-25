#include <stdio.h>
#include <stdlib.h>
#include <string.h>



typedef enum fault_type{
    MD5_HASH,SHA256_HASH,BITCOIN,OLD_VIRUS
}fault_type;

typedef enum events{
	created,opened,modified,deleted
}event_t;

typedef struct entry{
    char file[512];
    fault_type type;
    event_t event;
    struct entry* next;
}entry;

entry* insert(entry* head,entry* new);

void print_list2(entry* head);

entry* create_node(char* name ,fault_type t, event_t e);

entry* lookup(entry* head, char* name, int len);

void print_list(entry* head);
