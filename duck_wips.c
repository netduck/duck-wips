#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int main(int argc,char *argv[]){
    char *black_list[argc];
    for(int i=1;i<argc;i++){
        black_list[i-1] = argv[i];
        printf("%s\n",argv[i]);
    }
    printf("black_list\n");
    for(int i=0;i<argc-1;i++){
        printf("%s\n",black_list[i]);
    }
    
}