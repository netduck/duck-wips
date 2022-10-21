#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

void Eliminate(char *str, char* ch)
{
    for (; *str != '\0'; str++)//종료 문자를 만날 때까지 반복
    {
        if (*str == *ch)//ch와 같은 문자일 때
        {
            strcpy(str, str + 1);
            str--;
        }
    }
}

int main(int argc,char *argv[]){
    char *black_list[argc];
    for(int i=1;i<argc;i++){
        Eliminate(argv[i],":");
        black_list[i-1] = argv[i];
    }
    for(int i=0;i<argc-1;i++){
        printf("%s",black_list[i]);
    }
    
}