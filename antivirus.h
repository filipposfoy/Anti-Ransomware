
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <sys/inotify.h>
#include <regex.h>
#include "utilities/list.h"
#include <poll.h>
#include <ctype.h> 
#include <curl/curl.h>

#define MAX_BUF_SIZE 4096 

unsigned int files_searched = 0;
unsigned int infected = 0;


typedef struct coeffs {
    int a;
    int b;
    int c;
}coeffs;

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);

void findTrinomialConstants(int x1, int y1, int x2, int y2, int x3, int y3, coeffs* sun);


void monitor_directory(char* base_dir);

void print_info(char* message);

int main(int argc, char** argv);

entry* scan_directories(const char* base_dir, entry* list, int flag,regex_t *rgx);


entry* check_file(char *filename,entry* list);

void slice_key(char* num);

entry* handle_monitor_prints(struct inotify_event *e, entry* head);

char* char_to_hexstring(const char* char_string);

int check_MD5(FILE* fptr);

int check_SHA256(FILE* fptr);

int searchInFile(FILE *file);

entry* inspect_file(char* filename, regex_t *rgx,entry* head);


entry* lookup_for_virus_events(entry* head);

int searchVirusSignature(FILE *file);

entry* check_domain(char* filename,char* domain,entry* head);