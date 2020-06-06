#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include "ieee80211.h"
#include "ieee80211_radiotap.h"
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef enum _IEEE80211_ENCRYPTION
{
    IEEE80211_ENCRYPTION_UNKNOWN,
    IEEE80211_ENCRYPTION_OPEN,
    IEEE80211_ENCRYPTION_WEP,
    IEEE80211_ENCRYPTION_WPA,
    IEEE80211_ENCRYPTION_WPA2,
    IEEE80211_ENCRYPTION_WPA2WPA
} IEEE80211_ENCRYPTION;

struct radio_header
{
    uint8_t vision;
    uint8_t pad;
    uint16_t len;
    uint32_t present1;
    uint32_t present2;
    uint8_t flag;
    uint8_t rate;
    uint16_t channel_freque;
    uint16_t channel_flag;
    uint8_t signal;
    uint8_t padding;
    uint16_t RX_flag;
    uint8_t signal2;
    uint8_t antena;
} __attribute__((packed));

struct frame_info
{
    char ssid[100];
    uint8_t signal;
    uint8_t channel;
    uint8_t bssid[IEEE80211_ADDR_LEN];
    IEEE80211_ENCRYPTION enc;
};

struct tag
{
    uint8_t tag_name;
    uint8_t len;
    uint8_t data[0];
} __attribute__((packed));

struct vendor_tag
{
    uint8_t tag_name;
    uint8_t len;
    uint32_t oui : 24;
    uint8_t oui_type;
    uint8_t data[0];
} __attribute__((packed));

struct frame_info all_ap[100];
int total_ap = 0;

int is_eaqul(uint8_t com1[], uint8_t com2[], int len);

void *print(void *arg)
{
    while (1)
    {
        sleep(1);
        system("clear");

        for (int i = 0; i < total_ap; i++)
        {
            printf("SSID = %s ", all_ap[i].ssid);
            printf("BSSID = %02x:%02x:%02x:%02x:%02x:%02x ", all_ap[i].bssid[0], all_ap[i].bssid[1], all_ap[i].bssid[2], all_ap[i].bssid[3], all_ap[i].bssid[4], all_ap[i].bssid[5]);
            printf("SIGNAL = %d ", (int)all_ap[i].signal - 256);
            printf("CHANNEL = %d ", all_ap[i].channel);

            switch (all_ap[i].enc)
            {
            case IEEE80211_ENCRYPTION_WPA:
                printf("ECN = WPA");
                break;

            case IEEE80211_ENCRYPTION_OPEN:
                printf("ECN = OPEN");
                break;

            case IEEE80211_ENCRYPTION_WPA2:
                printf("ECN = WPA2");
                break;

            case IEEE80211_ENCRYPTION_WPA2WPA:
                printf("ECN = WPA/WPA2");
                break;

            case IEEE80211_ENCRYPTION_WEP:
                printf("ECN = WEP");
                break;
            }
            printf("\n");
        }
    }
}

int main()
{
    pcap_if_t *alldevs;
    pcap_t *adhandle;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int no;
    int i;

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

    int status;
    pthread_t p_thread = pthread_create(&p_thread, NULL, print, NULL);
    pthread_join(p_thread, (void **)&status);

    while (1)
    {
        int datalen = 0;
        struct frame_info info;
        int res;
        int i;

        struct pcap_pkthdr *header;
        const unsigned char *pkt_data;

        res = pcap_next_ex(adhandle, &header, &pkt_data);
        if (res == 0)
            continue;

        struct radio_header *rh;
        rh = (struct radio_header *)(pkt_data);
        datalen += rh->len;
        info.signal = rh->signal;

        struct ieee80211_frame *fh;
        fh = (struct ieee80211_frame *)(pkt_data + datalen);

        uint8_t type;
        uint8_t sub;

        type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        sub = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        if (type == IEEE80211_FC0_TYPE_MGT && sub == IEEE80211_FC0_SUBTYPE_BEACON)
        {
            datalen += sizeof(*fh);

            memcpy(info.bssid,fh->i_addr3,IEEE80211_ADDR_LEN);

            ieee80211_mgt_beacon_t fixed = (ieee80211_mgt_beacon_t)(pkt_data + datalen);
            datalen += sizeof(uint8_t) * 12;

            uint8_t captemp = IEEE80211_BEACON_CAPABILITY(fixed);

            if (captemp == IEEE80211_CAPINFO_PRIVACY)
            {
                info.enc = IEEE80211_ENCRYPTION_WEP;
            }
            else
            {
                info.enc = IEEE80211_ENCRYPTION_OPEN;
            }

            do
            {
                struct tag *th;
                th = (struct tag *)(pkt_data + datalen);

                if (th->tag_name == IEEE80211_ELEMID_SSID)
                {
                    if (th->len != 0 && th->data[0] != 0x00)
                    {
                        memset(info.ssid, 0, sizeof(info.ssid));
                        memcpy(info.ssid, th->data, th->len);
                    }
                    else
                    {
                        strcpy(info.ssid, "secret");
                    }
                }

                else if (th->tag_name == IEEE80211_ELEMID_DSPARMS)
                {
                    info.channel = th->data[0];
                }

                else if (th->tag_name == IEEE80211_ELEMID_RSN)
                {
                    info.enc = IEEE80211_ENCRYPTION_WPA2;
                }

                else if (th->tag_name == IEEE80211_ELEMID_VENDOR)
                {
                    struct vendor_tag *vh;
                    vh = (struct vendor_tag *)(pkt_data + datalen);

                    if (vh->oui == WPA_OUI && vh->oui_type == WPA_OUI_TYPE)
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

                datalen += (th->len + sizeof(uint8_t) * 2);

                //printf("%s,%d,%d\n", info.ssid, (int)info.signal-256,info.channel);

            } while (datalen < (int)header->len);

            int count = 0;

            for (i = 0; i < total_ap; i++)
            {
                if (is_eaqul(all_ap[i].bssid, info.bssid, IEEE80211_ADDR_LEN))
                {
                    count = 1;
                    break;
                }
            }

            if (!count)
            {
                all_ap[total_ap] = info;
                total_ap++;
            }
            else
            {
                all_ap[i].signal = info.signal;
            }
        }

       else if(type == IEEE80211_FC0_TYPE_DATA && sub == IEEE80211_FC0_SUBTYPE_QOS)
       {
        
       }
    }
}

int is_eaqul(uint8_t com1[], uint8_t com2[], int len)
{
    int count = 1;
    int i;

    for (i = 0; i < len; i++)
    {
        if (com1[i] == com2[i])
        {
            continue;
        }
        else
        {
            count = 0;
            break;
        }
    }
    return count;
}