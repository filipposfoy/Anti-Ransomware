#include "list.h"


entry* insert(entry* head,entry* new){
    if(head == NULL){
        head = new;
    }else{
        entry* tmp = head;
        while(tmp->next!=NULL){
            tmp = tmp->next;
        }
        tmp->next = new;
    }
    return head;
}

entry* create_node(char* name ,fault_type t, event_t e){
    entry *new =(entry*) malloc(sizeof(entry));
    memset(new->file,'\0',256);
    strcpy(new->file,name);
    new->type = t;
    new->event = e;
    new->next = NULL;
    return new;
}

void print_list2(entry* head){
    if(head == NULL)
        return;
    entry* tmp = head;
    int i = 0;
    int index_1 = 0;
    int index_2 = 0;
    printf("|PATH   \t\t| FILE   | DOMAIN  | RESULT \n" );
    while(tmp!=NULL){
        for(i = 0;i<strlen(tmp->file);i++) {
            if(tmp->file[i] == '/'){
                index_2 = index_1;
                index_1 = i;
            }
        }
        printf("%s\n",tmp->file);
        for(i = 0; i<index_2;i++){
            printf("%c",tmp->file[i]);
        }
        printf(" ||");
        for(i = index_2+1; i<index_1; i++){
            printf("%c",tmp->file[i]);
        }
        
        printf(" ||");
        for(i = index_1+1; i<strlen(tmp->file);i++){
            printf("%c",tmp->file[i]);
        }
        printf(" ||");
        if(tmp->type == 0){
            printf("MALWARE");
        }else{
            printf("SAFE");
        }
        printf("\n");
        tmp = tmp->next;
    }
}

void print_list(entry* head){
    if(head == NULL){
        return;
    }
    entry* tmp = head;
    while(tmp!=NULL){
        printf("%s:", tmp->file);
        switch(tmp->type){
            case MD5_HASH:
            printf("REPORTED_MD5_HASH\n");
            break;
            case SHA256_HASH:
            printf("REPORTED_SHA256_HASH\n");
            break;
            case BITCOIN:
            printf("REPORTED_BITCOIN\n");
            break;
            case OLD_VIRUS:
            printf("REPORTED_VIRUS\n");
            break;
            default:
            break;
        }
        tmp = tmp->next;
    }
}

entry* lookup(entry* head , char* name , int len){
	if(head == NULL){
	return NULL;
	}
	entry* tmp = head;
	while(tmp!=NULL){
		if(strncmp(tmp->file,name,len) == 0){
			return tmp;
		}
		tmp = tmp->next;
	}
	return NULL;
}


