#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include "ieee80211.h"
#include "ieee80211_radiotap.h"
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

typedef enum _IEEE80211_ENCRYPTION
{
    IEEE80211_ENCRYPTION_UNKNOWN,
    IEEE80211_ENCRYPTION_OPEN,
    IEEE80211_ENCRYPTION_WEP,
    IEEE80211_ENCRYPTION_WPA,
    IEEE80211_ENCRYPTION_WPA2,
    IEEE80211_ENCRYPTION_WPA2WPA
} IEEE80211_ENCRYPTION;

struct beacon_info
{
    char ssid[100];
    uint8_t bssid[IEEE80211_ADDR_LEN];
    uint8_t channel;
    IEEE80211_ENCRYPTION enc;
    uint8_t signal;
    uint8_t dev[100][IEEE80211_ADDR_LEN];
    int total_dev;
};

struct radiotap_header
{
    uint8_t vision;
    uint8_t pad;
    uint16_t len;
    uint32_t present1;
    uint32_t present2;
    uint8_t flags;
    uint8_t rate;
    uint16_t channel_frequency;
    uint16_t channel_flag;
    uint8_t signal1;
    uint8_t padding;
    uint16_t rx_flag;
    uint8_t signal2;
    uint8_t antena;
} __attribute__((packed));

struct tag1
{
    uint8_t tag_name;
    uint8_t tag_len;
    uint8_t data[0];
} __attribute__((packed));

struct vender_info
{
    uint8_t tag_name;
    uint8_t tag_len;
    uint32_t tag_oui : 24;
    uint8_t tag_oui_type;
    uint8_t oui_data[0];
} __attribute__((packed));

struct beacon_info Buf_AP[100];
int total_ap = 0;

void *print(void *arg)
{
    while (1)
    {
        sleep(1);
        system("clear");

        for (int i = 0; i < total_ap; i++)
        {
            printf("SSID = %s, ", Buf_AP[i].ssid);
            printf("BSSID = %02X:%02X:%02X:%02X:%02X:%02X, ", Buf_AP[i].bssid[0], Buf_AP[i].bssid[1], Buf_AP[i].bssid[2], Buf_AP[i].bssid[3], Buf_AP[i].bssid[4], Buf_AP[i].bssid[5]);
            printf("SIGNAL = %d, ", (int)Buf_AP[i].signal - 256);
            printf("CHANNEL = %d, ", Buf_AP[i].channel);
            switch (Buf_AP[i].enc)
            {
            case IEEE80211_ENCRYPTION_WPA2:
                printf("ECN = WPA2");
                break;

            case IEEE80211_ENCRYPTION_WPA2WPA:
                printf("ECN = WPA/WPA2");
                break;

            case IEEE80211_ENCRYPTION_WEP:
                printf("ECN = WEP");
                break;

            case IEEE80211_ENCRYPTION_OPEN:
                printf("ECN = OPEN");
                break;
            }

            printf("\n");
            for (int j = 0; j < Buf_AP[i].total_dev; j++)
            {
                printf("    (DEV) %02X:%02X:%02X:%02X:%02X:%02X\n", Buf_AP[i].dev[j][0], Buf_AP[i].dev[j][1], Buf_AP[i].dev[j][2], Buf_AP[i].dev[j][3], Buf_AP[i].dev[j][4], Buf_AP[i].dev[j][5]);
            }
        }
    }
}

int is_equal(uint8_t com1[], uint8_t com2[], int len);

int main(int argc, char **argv)
{
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    int i = 0;
    int no;

    if (pcap_findalldevs(&alldevs, errbuf) < 0)
    {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d = alldevs; d; d = d->next)
    {
        printf("%d :  %s\n", ++i, (d->description) ? (d->description) : (d->name));
    }

    printf("number : ");
    scanf("%d", &no);

    if (!(no > 0 && no <= i))
    {
        printf("number error\n");
        return 1;
    }

    for (d = alldevs, i = 0; d; d = d->next)
    {
        if (no == ++i)
            break;
    }

    if (!(adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)))
    {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs);

    // pcap_t *adhandle2;
    //         char errbuf2[PCAP_ERRBUF_SIZE];
    //         pcap_if_t *alldevs2;
    //         pcap_if_t *d2;
    //         struct pcap_addr *a2;
    //         i = 0;
    //         int no2;

    //         if (pcap_findalldevs(&alldevs2, errbuf2) < 0)
    //         {
    //             printf("pcap_findalldevs error\n");
    //             return 1;
    //         }

    //         for (d2 = alldevs2; d2; d2 = d2->next)
    //         {
    //             printf("%d :  %s\n", ++i, (d2->description) ? (d2->description) : (d2->name));
    //         }

    //         printf("number : ");
    //         scanf("%d", &no2);

    //         if (!(no2 > 0 && no2 <= i))
    //         {
    //             printf("number error\n");
    //             return 1;
    //         }

    //         for (d2 = alldevs2, i = 0; d2; d2 = d2->next)
    //         {
    //             if (no2 == ++i)
    //                 break;
    //         }

    //         if (!(adhandle2 = pcap_open_live(d2->name, 65536, 1, 1000, errbuf2)))
    //         {
    //             printf("pcap_open_live error %s\n", d2->name);
    //             pcap_freealldevs(alldevs2);
    //             return -1;
    //         }

    //         pcap_freealldevs(alldevs2);

    int status;
    pthread_t p_thread = pthread_create(&p_thread, NULL, print, NULL);
    pthread_join(p_thread, (void **)&status);

    while (1)
    {
        struct pcap_pkthdr *header;
        const unsigned char *pkt_data;
        int datalen = 0;
        int res;
        int i;

        res = pcap_next_ex(adhandle, &header, &pkt_data);
        if (res == 0)
            continue;

        struct beacon_info info;
        struct radiotap_header *rah;
        rah = (struct radiotap_header *)(pkt_data);
        datalen += rah->len;

        struct ieee80211_frame *fh;
        fh = (struct ieee80211_frame *)(pkt_data + datalen);

        uint8_t sub = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
        uint8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

        if (type == IEEE80211_FC0_TYPE_MGT && sub == IEEE80211_FC0_SUBTYPE_BEACON)
        {
            info.signal = rah->signal1;

            datalen += sizeof(*fh);
            memcpy(info.bssid, fh->i_addr3, IEEE80211_ADDR_LEN);
            //printf("%02X : %02X : %02X : %02X : %02X : %02X\n",info.bssid[0],info.bssid[1],info.bssid[2],info.bssid[3],info.bssid[4],info.bssid[5]);

            uint16_t captemp;

            ieee80211_mgt_beacon_t fixed = (ieee80211_mgt_beacon_t)(pkt_data + datalen);
            datalen += sizeof(uint8_t) * 12; //skip fixed parameters

            captemp = IEEE80211_BEACON_CAPABILITY(fixed);

            if (captemp & IEEE80211_CAPINFO_PRIVACY)
            {
                info.enc = IEEE80211_ENCRYPTION_WEP;
            }

            else
            {
                info.enc = IEEE80211_ENCRYPTION_OPEN;
            }

            do
            {
                struct tag1 *tag1_info;
                tag1_info = (struct tag1 *)(pkt_data + datalen);

                if (tag1_info->tag_name == IEEE80211_ELEMID_SSID)
                {
                    if (tag1_info->tag_len != 0 || tag1_info->data != 0x00)
                    {
                        memset(info.ssid, 0, sizeof(info.ssid));
                        memcpy(info.ssid, tag1_info->data, tag1_info->tag_len);
                    }
                    else
                    {
                        strcpy(info.ssid, "secret");
                    }

                    //printf("%s ",info.ssid);
                }

                else if (tag1_info->tag_name == IEEE80211_ELEMID_DSPARMS)
                {
                    info.channel = tag1_info->data[0];
                    //printf("%d\n ",info.channel);
                }

                else if (tag1_info->tag_name == IEEE80211_ELEMID_RSN)
                {
                    info.enc = IEEE80211_ENCRYPTION_WPA2;
                }

                if (tag1_info->tag_name == IEEE80211_ELEMID_VENDOR)
                {
                    struct vender_info *v_info;
                    v_info = (struct vender_info *)(pkt_data + datalen);

                    if (v_info->tag_oui == WPA_OUI && v_info->tag_oui_type == WPA_OUI_TYPE)
                    {
                        if (info.enc == IEEE80211_ENCRYPTION_WPA2)
                        {
                            info.enc = IEEE80211_ENCRYPTION_WPA2WPA;
                        }
                        else
                        {
                            info.enc = IEEE80211_ENCRYPTION_WPA;
                        }
                    }
                }

                datalen += (tag1_info->tag_len + sizeof(uint8_t) * 2);

            } while (datalen < (int)header->len);

            int i = 0;
            int count = 0;

            for (i = 0; i < total_ap; i++)
            {
                if (is_equal(Buf_AP[i].bssid, info.bssid, IEEE80211_ADDR_LEN))
                {
                    count = 1;
                    break;
                }
            }

            if (!count)
            {
                info.total_dev = 0;
                Buf_AP[total_ap] = info;
                total_ap++;
            }
            else
            {
                Buf_AP[i].signal = info.signal;
            }
        }

        else if (type == IEEE80211_FC0_TYPE_DATA && sub == IEEE80211_FC0_SUBTYPE_QOS)
        {
            struct ieee80211_qosframe *qh;
            qh = (struct ieee80211_qosframe *)(pkt_data + datalen);
            uint8_t qostemp = qh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

            if (qostemp == IEEE80211_FC1_DIR_FROMDS)
            {
                // printf("IOT = %02X : %02X : %02X : %02X : %02X : %02X ",qh->i_addr1[0],qh->i_addr1[1],qh->i_addr1[2],qh->i_addr1[3],qh->i_addr1[4],qh->i_addr1[5]);
                // printf("AP = %02X : %02X : %02X : %02X : %02X : %02X \n",qh->i_addr2[0],qh->i_addr2[1],qh->i_addr2[2],qh->i_addr2[3],qh->i_addr2[4],qh->i_addr2[5]);

                int count = 0;

                for (i = 0; i < total_ap; i++)
                {
                    if (is_equal(Buf_AP[i].bssid, qh->i_addr2, IEEE80211_ADDR_LEN))
                    {
                        count = 1;
                        break;
                    }
                }

                if (count)
                {
                    count = 0;
                    int j;
                    for (j = 0; j < Buf_AP[i].total_dev; j++)
                    {
                        if (is_equal(Buf_AP[i].dev[j], qh->i_addr1, IEEE80211_ADDR_LEN))
                        {
                            count = 1;
                            break;
                        }
                    }

                    if (!count)
                    {
                        memcpy(Buf_AP[i].dev[Buf_AP[i].total_dev], qh->i_addr1, IEEE80211_ADDR_LEN);
                        Buf_AP[i].total_dev++;
                    }
                }
            }

            else if (qostemp == IEEE80211_FC1_DIR_TODS)
            {
                //  printf("IOT = %02X : %02X : %02X : %02X : %02X : %02X ",qh->i_addr2[0],qh->i_addr2[1],qh->i_addr2[2],qh->i_addr2[3],qh->i_addr2[4],qh->i_addr2[5]);
                // printf("AP = %02X : %02X : %02X : %02X : %02X : %02X \n",qh->i_addr1[0],qh->i_addr1[1],qh->i_addr1[2],qh->i_addr1[3],qh->i_addr1[4],qh->i_addr1[5]);
                int count = 0;

                for (i = 0; i < total_ap; i++)
                {
                    if (is_equal(Buf_AP[i].bssid, qh->i_addr1, IEEE80211_ADDR_LEN))
                    {
                        count = 1;
                        break;
                    }
                }

                if (count)
                {
                    count = 0;
                    int j;
                    for (j = 0; j < Buf_AP[i].total_dev; j++)
                    {
                        if (is_equal(Buf_AP[i].dev[j], qh->i_addr2, IEEE80211_ADDR_LEN))
                        {
                            count = 1;
                            break;
                        }
                    }

                    if (!count)
                    {
                        memcpy(Buf_AP[i].dev[Buf_AP[i].total_dev], qh->i_addr2, IEEE80211_ADDR_LEN);
                        Buf_AP[i].total_dev++;
                    }
                }
            }
        }

        // else if (type == IEEE80211_FC0_TYPE_MGT && 
        // (sub == IEEE80211_FC0_SUBTYPE_AUTH || sub == IEEE80211_FC0_SUBTYPE_DEAUTH)||
        // (sub == IEEE80211_FC0_SUBTYPE_ASSOC_REQ||sub==IEEE80211_FC0_SUBTYPE_ASSOC_RESP)||
        // (sub == IEEE80211_FC0_SUBTYPE_REASSOC_REQ||sub==IEEE80211_FC0_SUBTYPE_REASSOC_RESP))
        // {
        //      uint8_t packet[2500];
        //      memcpy(packet,pkt_data,header->len);
        //      pcap_sendpacket(adhandle2,pkt_data,header->len);
        // }

        //printf("%d\n",((int)info.signal)-256);
    }

    return 0;
}

int is_equal(uint8_t com1[], uint8_t com2[], int len)
{
    int count = 1;
    int i = 0;
    for (i = 0; i < len; i++)
    {
        if (com1[i] == com2[i])
            continue;
        else
        {
            count = 0;
            break;
        }
    }

    return count;
}