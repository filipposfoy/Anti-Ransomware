#include "antivirus.h"

#define MAX_BUF_SIZE 4096 // Increased buffer size


int main(int argc, char** argv){
    entry *list = NULL;
    char* message = malloc(strlen(argv[2]) + 32);
    char* message1 = "Proccesed %u files.Found %u infected\n";
    char message2[64];
    regex_t rgx;
    strncat(message,"Scanning directory ",20);
    if(regcomp(&rgx,"[a-zA-Z0-9-]+\\.(com|org|net|edu|gov|mil|int|us|uk|de|jp|cn|fr|in|au|arpa|xyz|info|club|app|blog|shop|online|store|рф|中国|भारत|みんな)",REG_EXTENDED) != 0 ){
        printf("regex compilation error\n");
        exit(0);
    }
    strncat(message,argv[2],strlen(argv[2]));
    print_info("Application Started");
    if(argc == 3 && !strcmp(argv[1],"scan")){
        print_info(message);
        print_info("Searching..");
        list = scan_directories(argv[2],list,1,&rgx);
        print_info("Operation finished");
        sprintf(message2,message1,files_searched,infected);
        print_info(message2);
            print_list(list);
        }else if(argc == 3 && !strcmp(argv[1],"monitor") ){
            monitor_directory(argv[2]);
        }else if(argc == 3 && !strcmp(argv[1],"slice")){
            slice_key(argv[2]);
        }else if (argc == 3 && !strcmp(argv[1],"inspect")){
            list = scan_directories(argv[2],list,0,&rgx);
            print_list2(list);
        }else if(argc >= 8 && !strcmp(argv[1],"unlock")){
            coeffs sun;
            char *s1 = "Received %d different shares";
            char *s2 = "Computed that a=%d and b=%d";
            char* s3 = "Encryption key is %d";
            char s1_2[64];
            int x1 = atoi(argv[2]);
            int y1 = atoi(argv[3]);
            int x2 = atoi(argv[4]);
            int y2 = atoi(argv[5]);
            int x3 = atoi(argv[6]);
            int y3 = atoi(argv[7]);
            findTrinomialConstants(x1,y1,x2,y2,x3,y3,&sun);
        sprintf(s1_2,s1,(argc/2 - 1));
        print_info(s1_2);
        sprintf(s1_2,s2,sun.a,sun.b);
        print_info(s1_2);
        sprintf(s1_2,s3,sun.c);
        print_info(s1_2);
    }

    

    free(message);
}
double determinant(double a, double b, double c, double d, double e, double f, double g, double h, double i) {
    return a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
}

void findTrinomialConstants(int x1, int y1, int x2, int y2, int x3, int y3, coeffs* sun) {
    double main_determinant = determinant(x1 * x1, x1, 1, x2 * x2, x2, 1, x3 * x3, x3, 1);
    double a_determinant = determinant(y1, x1, 1, y2, x2, 1, y3, x3, 1);
    double b_determinant = determinant(x1 * x1, y1, 1, x2 * x2, y2, 1, x3 * x3, y3, 1);
    double c_determinant = determinant(x1 * x1, x1, y1, x2 * x2, x2, y2, x3 * x3, x3, y3);

    sun->a = a_determinant / main_determinant;
    sun->b = b_determinant / main_determinant;
    sun->c = c_determinant / main_determinant;
}



void slice_key(char* num){
    int key = atoi(num);
    int constants[2];
    long sum = 0;
    srand(time(NULL));
    for(int i = 0;i<2;i++){
        constants[i] = rand() % 10000;
    }
    for(int i = 1;i<=10;i++){
        sum += key;
        sum += i*constants[0];
        sum += i*i*constants[1];
        printf("(%d,%ld)\n", i, sum);
        sum = 0;
    }   
}   

void monitor_directory(char* base_dir){
    int fd;
    int wd;
    int bufsize = sizeof(struct inotify_event) + strlen(base_dir) + 128 + 1;
    size_t len;
    entry* head = NULL;
    struct pollfd p;
    void* buf = malloc(bufsize);
    struct inotify_event *e = (struct inotify_event*) buf;
    if((fd = inotify_init()) == -1){
        perror("");
        exit(-1);
    }
    wd = inotify_add_watch(fd,base_dir,IN_ACCESS | IN_ATTRIB | IN_CLOSE_WRITE |  IN_CLOSE_NOWRITE | IN_CREATE | IN_DELETE |
     IN_DELETE_SELF | IN_MODIFY | IN_OPEN);
    if(wd == -1){
        perror("");
        exit(-1);
    }
    p.fd = fd;
    p.events = POLLIN;
    while(1){
	int ret = poll(&p,1,-1);
        if(ret > 0 ){
            if(p.revents & POLLIN){
                len = read(fd,buf,bufsize);
               head =  handle_monitor_prints(e,head);
            }    
        }else{
            perror("poll");
            exit(EXIT_FAILURE);
        }
    }
    free(buf);
}


entry* scan_directories(const char* base_dir, entry* list, int flag,regex_t *rgx){
    DIR *directory;
    struct dirent *entry;
    char next[512];
    memset(next,'\0',512);
    directory = opendir(base_dir);
    if(directory == NULL){
        perror("");
        fprintf(stderr,"directory %s could not be opened\n", base_dir);
        exit(-1);
    }
    while((entry=readdir(directory))!=NULL){
        if(entry->d_type == DT_REG){
            strncpy(next,base_dir,strlen(base_dir));
            next[strlen(next)] = '/';
            strncat(next,entry->d_name,strlen(entry->d_name));
            if(flag ==1){
                list = check_file(next,list);
                files_searched++;
            }else{
                list =inspect_file(next,rgx,list);
            }           
            memset(next,'\0',512);
        }else if (entry->d_type == DT_DIR && strcmp(entry->d_name,".") != 0  && strcmp(entry->d_name,"..") != 0){
            strcpy(next,base_dir);
            next[strlen(next)] = '/';
            next[strlen(next)] ='\0';
            strncat(next,entry->d_name,strlen(entry->d_name));
            if(flag == 1){
                list = scan_directories(next,list,1,rgx);
            }else{
                list = scan_directories(next,list,0,rgx);
            }    
            memset(next,'\0',512);
        }    
    }
    return list;
}

entry* inspect_file(char* filename, regex_t *rgx,entry* head) {
    FILE* fptr = fopen(filename, "r");
    if (fptr == NULL) {
        perror("Error opening file");
        return NULL;
    }

    regmatch_t matches[1];
    char matched_buf[MAX_BUF_SIZE]; 
    char buf[MAX_BUF_SIZE];
    char c;
    int i = 0;
    int matched_index = 0;
    while ((c = fgetc(fptr)) != EOF) {
        if (isprint(c) && !iscntrl(c)) {
            buf[i] = c;
            i++;
        } else {
            buf[i] = '\0';
            if (regexec(rgx, buf, 1, matches, 0) == 0) {
                int match_length = matches[0].rm_eo - matches[0].rm_so;
                strncpy(&matched_buf[matched_index], &buf[matches[0].rm_so], match_length);
                matched_index += match_length;
                matched_buf[matched_index] = '\0';
                head = check_domain(filename,matched_buf,head);
                memset(matched_buf,'\0',MAX_BUF_SIZE);
            }
            memset(buf, '\0', MAX_BUF_SIZE);
            i = 0;
            matched_index = 0;
        } 
    }
    return head;
    fclose(fptr);
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        /* out of memory! */
        fprintf(stderr, "realloc() failed\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

entry* check_domain(char* filename,char* domain,entry* head){
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char url[MAX_BUF_SIZE];
    
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error initializing libcurl\n");
        exit(0);
    }

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  // will be grown as needed by the realloc above
    chunk.size = 0;             // no data at this point

    snprintf(url, MAX_BUF_SIZE, "https://family.cloudflare-dns.com/dns-query?name=%s", domain);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    headers = curl_slist_append(headers, "accept:application/dns-json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.memory);
        exit(0);
    }
    memset(url,'\0',MAX_BUF_SIZE);
    if(strstr(chunk.memory,"EDE(16): Censored")){
        strcpy(url,filename);
        url[strlen(url)] =  '/';
        strcat(url,domain);
        head = insert(head,create_node(url,0,-1));
       // printf("Malicious %s\n" , url );

     }else{
        strcpy(url,filename);
        url[strlen(url)] =  '/';
        strcat(url,domain);
        head = insert(head,create_node(url,1,-1));
       // printf("URL :: %s\n" , url );
     }
     memset(url,'\0',MAX_BUF_SIZE);

    curl_easy_cleanup(curl);
    free(chunk.memory);
    return head;
}
 
entry* check_file(char *filename,entry *list){
    FILE *fptr = fopen(filename,"r");
    if(fptr == NULL){
        perror("");
        exit(-1);
    }
    if(!check_MD5(fptr)){
        list = insert(list,create_node(filename,MD5_HASH,0));
        infected++;
    }
    rewind(fptr);
    if(!check_SHA256(fptr)){
        list = insert(list,create_node(filename,SHA256_HASH,0));
        infected++;
    }
    rewind(fptr);
    if(!searchVirusSignature(fptr)){
        list = insert(list,create_node(filename,OLD_VIRUS,0));
        infected++;
    }
    rewind(fptr);
    if(!searchInFile(fptr)){
        list = insert(list,create_node(filename,BITCOIN,0));
        infected++;
    }
    fclose(fptr);
    return list;
}

int ends_with_locked(const char *name) {
    size_t len = strlen(name);
    const char *suffix = ".locked";
    size_t suffix_len = strlen(suffix);

    if (len < suffix_len)
        return 0;

    return strncmp(name + len - suffix_len, suffix, suffix_len) == 0;
}

entry* handle_monitor_prints(struct inotify_event *e,entry* head){
    if(e->mask == 1073741856 || e->mask == 1073741825){
	return head;
	}
	entry* tmp = NULL;   
    	if (e->mask & IN_CREATE){
	head = insert(head,create_node(e->name,0,created));
        printf("File %s was created.\n", e->name);
	} else if (e->mask & IN_DELETE){
	head = insert(head,create_node(e->name,0,deleted));
         printf("File %s was deleted.\n", e->name);
	}else if(e->mask & IN_OPEN){
	head = insert(head,create_node(e->name,0,opened));
	printf("File %s was opened.\n", e->name);
	}else if(e->mask  & IN_ACCESS){
	printf("File %s was accessed.\n",e->name);
	}else if (e->mask & IN_CLOSE_WRITE){
	printf("File %s that was opened for writing has been closed\n", e->name);
	}else if (e->mask & IN_MODIFY){
	head = insert(head,create_node(e->name,0,modified));
	printf("File %s has been stored\n",e->name);
	}
	if((tmp = lookup_for_virus_events(head)) != NULL){
		printf("[WARN] RANSOMWARE ATTACK DETECTED AT FILE %s\n",tmp->file);
	} 
	
	return head;
}

entry *lookup_for_virus_events(entry* head){
	entry* tmp = head;
	event_t current_state =  -1;
	char buf[512] ={'0'};
    entry* tmp2 ;
	while(tmp!=NULL){
		if(tmp->event == opened && current_state == -1){
			current_state = opened;
			strcpy(buf,tmp->file);
            tmp2 = tmp;
            while(tmp2!=NULL){
                if(tmp2->event == created && current_state == opened && (strstr(tmp2->file,buf)!=NULL) && ends_with_locked(tmp2->file) && (strlen(tmp2->file) == strlen(buf) + 7)){
			        current_state = created;
		        }else if(tmp2->event == modified && current_state == created && (strstr(tmp2->file,buf)!=NULL) && ends_with_locked(tmp2->file) && (strlen(tmp2->file) == strlen(buf) + 7)){
			        current_state = modified;
		        }else if(tmp2->event == deleted && current_state == modified && (strcmp(buf,tmp2->file) ==0)){
			        if(tmp2->type != -1){
				        tmp2->type = -1;
				        return tmp2;
			        }
                    break;
		        }
                tmp2 = tmp2->next;   
            }
            current_state = -1;
        }    
    	tmp = tmp->next;
	}	
	return NULL;
}


int searchVirusSignature(FILE *file) {
    unsigned char target[] = {
        0x98, 0x1d, 0x00, 0x00, 0xec, 0x33, 0xff, 0xff, 
        0xfb, 0x06, 0x00, 0x00, 0x00, 0x46, 0x0e, 0x10,
    };
    size_t target_length = 16;

    const size_t buffer_size = 1024;
    unsigned char buffer[buffer_size];
    size_t j;
    size_t bytes_read;
    int partial_match = 0; 

    while ((bytes_read = fread(buffer, 1, buffer_size, file)) > 0) {
        for (size_t i = 0; i < bytes_read; ++i) {
            if (buffer[i] == target[0]) {
                for (j = 1; j < target_length && i + j < bytes_read; ++j) {
                    if (buffer[i + j] != target[j]) {
                        break;
                    }
                }
                if (j == target_length) {
                    return 0; 
                } else if (i + j == bytes_read) {
                    partial_match = 1;
                    break;
                }
            }
        }

        if (partial_match) {
            fseek(file, -j + 1, SEEK_CUR); 
            partial_match = 0;
        }
    }

    return 1;
}


int check_MD5(FILE* fptr){

    char md5_final[MD5_DIGEST_LENGTH+1];
    char *indicator = "85578cd4404c6d586cd0ae1b36c98aca";
    unsigned int bytes_hashed = 0;
    char chunks[1024];
    MD5_CTX mdContext;
    MD5_Init(&mdContext);
    
    size_t bytes_read; 
    md5_final[MD5_DIGEST_LENGTH] = '\0';

    while ((bytes_read = fread(chunks, 1, sizeof(chunks), fptr)) > 0){
        bytes_hashed += bytes_read; 
        MD5_Update(&mdContext, chunks, bytes_read);
    }
    MD5_Final(md5_final, &mdContext);
   
    if(strncmp(char_to_hexstring(md5_final),indicator,16) == 0){
        return 0;
    }
    return 1;
}

int check_SHA256(FILE* fptr){
    char sha256_final[SHA256_DIGEST_LENGTH+1];
    char *indicator ="d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
    unsigned int bytes_hashed = 0;
    char chunks[1024];
    SHA256_CTX shaContext;
    SHA256_Init(&shaContext);

    sha256_final[SHA256_DIGEST_LENGTH] = '\0';
    
    size_t bytes_read; 

    while ((bytes_read = fread(chunks, 1, sizeof(chunks), fptr)) > 0){
        bytes_hashed += bytes_read; 
        SHA256_Update(&shaContext, chunks, bytes_read);
    }

    SHA256_Final(sha256_final, &shaContext);
    if(strncmp(char_to_hexstring(sha256_final),indicator,32) == 0){
        return 0;
    }
    return 1;
}

int searchInFile(FILE *file) {
    char buffer[1024]; 
    size_t bytes_read;
    char search_string[42] = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
    
    int matches = 0;
    
    while ((bytes_read = fread(buffer, 1, 1024, file)) > 0) {
        for (int i = 0; i < bytes_read; i++) {
            if (buffer[i] == search_string[matches]) {
                matches++;
                if (matches == 42) {
                    return 0;
                }
            } else {
                matches = 0;
            }
        }
    }
    
    return 1;
}


char* char_to_hexstring(const char* char_string) {
    size_t len = strlen(char_string);
    char* hex_string = (char*)malloc((2 * len + 1) * sizeof(char));

    if (hex_string == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    size_t i;
    for (i = 0; i < len; ++i) {
        sprintf(hex_string + 2 * i, "%02x", (unsigned char)char_string[i]); 
    }
    hex_string[2 * len] = '\0'; 
    
    return hex_string;
}


void print_info(char* message){
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    printf("[INFO] [%d] [%d-%02d-%02d %02d:%02d:%02d] %s\n",getpid(), tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, message);
}
