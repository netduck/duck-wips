#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

void delete_char(char *str, char* ch)
{
    for (; *str != '\0'; str++)//NULL까지 반복
    {
        if (*str == *ch)//같은 글자라면
        {
            strcpy(str, str + 1);
            str--;
        }
    }
}

int main(int argc,char *argv[]){
    char *black_list[argc];
    for(int i=1;i<argc;i++){
        delete_char(argv[i],":");
        black_list[i-1] = argv[i];
    }
    for(int i=0;i<argc-1;i++){
        printf("%s\n",black_list[i]);
    }
    
}