#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int main(int argc,char *argv[]){
    char black_list[][];
    for(int i=1;i<argc;i++){
        printf("%s",argv[i]);
    }
}