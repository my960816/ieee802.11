#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include "ieee80211.h"
#include "ieee80211_radiotap.h"
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rc4.h>
#include "wpa_Decrypt.h"

struct options
{
    unsigned char passphrase[65];
    unsigned char pmk[32];
    unsigned char ssid[36];
};

struct addr
{
    uint8_t bssid[IEEE80211_ADDR_LEN];
    uint8_t dev[IEEE80211_ADDR_LEN];
};

struct LLC
{
    uint8_t dsap;
    uint8_t ssap;
    uint8_t cf;
    uint8_t Org_Code[3];
    uint16_t type;
} __attribute__((packed));

struct EAP_info
{
    uint8_t version;
    uint8_t type;
    uint16_t len;
    uint8_t key_type;
    uint16_t key_info;
    uint16_t key_len;
    uint64_t replay_counter;
    uint8_t key_nonce[32];
    uint8_t key_iv[16];
    uint8_t key_rsc[8];
    uint8_t key_id[8];
    uint8_t MIC[16];
    uint16_t data_len;
    uint8_t data[0];
} __attribute__((packed));

struct tkip
{
    uint8_t tkip[8];
} __attribute__((packed));

int is_key;
unsigned char TK[16];
unsigned char mic[20];

int is_equal(uint8_t com1[], uint8_t com2[], int len);

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

    pcap_t *adhandle2;
    char errbuf2[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs2;
    pcap_if_t *d2;
    struct pcap_addr *a2;
    i = 0;
    int no2;

    if (pcap_findalldevs(&alldevs2, errbuf2) < 0)
    {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d2 = alldevs2; d2; d2 = d2->next)
    {
        printf("%d :  %s\n", ++i, (d2->description) ? (d2->description) : (d2->name));
    }

    printf("number : ");
    scanf("%d", &no2);

    if (!(no2 > 0 && no2 <= i))
    {
        printf("number error\n");
        return 1;
    }

    for (d2 = alldevs2, i = 0; d2; d2 = d2->next)
    {
        if (no2 == ++i)
            break;
    }

    if (!(adhandle2 = pcap_open_live(d2->name, 65536, 1, 1000, errbuf2)))
    {
        printf("pcap_open_live error %s\n", d2->name);
        pcap_freealldevs(alldevs2);
        return -1;
    }

    pcap_freealldevs(alldevs2);

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

        struct ieee80211_radiotap_header *rah;
        rah = (struct ieee80211_radiotap_header *)(pkt_data);
        datalen += rah->it_len;

        struct ieee80211_frame *fh;
        fh = (struct ieee80211_frame *)(pkt_data + datalen);

        uint8_t sub = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
        uint8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

        if (type == IEEE80211_FC0_TYPE_DATA && sub == IEEE80211_FC0_SUBTYPE_QOS)
        {
            struct ieee80211_qosframe *qosdata;
            qosdata = (struct ieee80211_qosframe *)(pkt_data + datalen);
            datalen += sizeof(*qosdata);

            struct addr info;
            info.bssid[0] = 0x70;
            info.bssid[1] = 0x5d;
            info.bssid[2] = 0xcc;
            info.bssid[3] = 0x35;
            info.bssid[4] = 0x5d;
            info.bssid[5] = 0x7a;

            info.dev[0] = 0x08;
            info.dev[1] = 0xae;
            info.dev[2] = 0xd6;
            info.dev[3] = 0xd2;
            info.dev[4] = 0x86;
            info.dev[5] = 0x8b;

            uint8_t qostemp = qosdata->i_fc[1] & IEEE80211_FC1_DIR_MASK;

            if (qostemp == IEEE80211_FC1_DIR_FROMDS || qostemp == IEEE80211_FC1_DIR_TODS)
            {
                if ((is_equal(info.bssid, qosdata->i_addr2, IEEE80211_ADDR_LEN) && is_equal(info.dev, qosdata->i_addr1, IEEE80211_ADDR_LEN)) ||
                    (is_equal(info.bssid, qosdata->i_addr1, IEEE80211_ADDR_LEN) && is_equal(info.dev, qosdata->i_addr2, IEEE80211_ADDR_LEN)))
                {
                    if (is_key == 0)
                    {
                        struct LLC *LLCh;
                        LLCh = (struct LLC *)(pkt_data + datalen);

                        if (LLCh->type == htons(0x888e))
                        {
                            datalen += sizeof(*LLCh);
                            unsigned char PMK[256];
                            struct EAP_info *E_info;
                            E_info = (struct EAP_info *)(pkt_data + datalen);
                            uint8_t Anonce[32];
                            uint8_t Nnonce[32];

                            if (ntohs(E_info->key_info) == 0x008a)
                            {
                                memcpy(Anonce, E_info->key_nonce, 32);

                                printf("Anonce : ");

                                for (i = 0; i < 32; i++)
                                {
                                    printf("%x", E_info->key_nonce[i]);
                                }
                                printf("\n");
                            }

                            else if (ntohs(E_info->key_info) == 0x010a)
                            {
                                memcpy(Nnonce, E_info->key_nonce, 32);

                                printf("Nnonce : ");

                                for (i = 0; i < 32; i++)
                                {
                                    printf("%x", E_info->key_nonce[i]);
                                }
                                printf("\n");

                                struct options opinfo = {0};
                                char ssid[] = "INFOLAP420_WPA2";
                                char pass[] = "info1234";

                                PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), (const unsigned char *)ssid, strlen(ssid), 4096, 32, opinfo.pmk);

                                printf("PMK : ");
                                for (i = 0; i < 32; i++)
                                {
                                    printf("%x", opinfo.pmk[i]);
                                }
                                printf("\n");
                                unsigned char pke[100] = {
                                    0x50,
                                    0x61,
                                    0x69,
                                    0x72,
                                    0x77,
                                    0x69,
                                    0x73,
                                    0x65,
                                    0x20,
                                    0x6B,
                                    0x65,
                                    0x79,
                                    0x20,
                                    0x65,
                                    0x78,
                                    0x70,
                                    0x61,
                                    0x6E,
                                    0x73,
                                    0x69,
                                    0x6F,
                                    0x6E,
                                    0x00,
                                };
                                unsigned char PTK[80] = {0};

                                int pkepo = 23;

                                if (info.bssid[0] < info.dev[0])
                                {
                                    memcpy(pke + pkepo, info.bssid, IEEE80211_ADDR_LEN);
                                    pkepo += IEEE80211_ADDR_LEN;
                                    memcpy(pke + pkepo, info.dev, IEEE80211_ADDR_LEN);
                                    pkepo += IEEE80211_ADDR_LEN;
                                }

                                else
                                {
                                    memcpy(pke + pkepo, info.dev, IEEE80211_ADDR_LEN);
                                    pkepo += IEEE80211_ADDR_LEN;
                                    memcpy(pke + pkepo, info.bssid, IEEE80211_ADDR_LEN);
                                    pkepo += IEEE80211_ADDR_LEN;
                                }

                                if (Anonce[0] < Nnonce[0])
                                {
                                    memcpy(pke + pkepo, Anonce, 32);
                                    pkepo += 32;
                                    memcpy(pke + pkepo, Nnonce, 32);
                                    pkepo += 32;
                                }

                                else
                                {
                                    memcpy(pke + pkepo, Nnonce, 32);
                                    pkepo += 32;
                                    memcpy(pke + pkepo, Anonce, 32);
                                    pkepo += 32;
                                }

                                for (i = 0; i < 4; i++)
                                {
                                    pke[99] = i;
                                    HMAC(EVP_sha1(), opinfo.pmk, 32, pke, 100, PTK + i * 20, NULL);
                                }

                                printf("PTK : ");
                                for (i = 0; i < 80; i++)
                                {
                                    printf("%X ", PTK[i]);
                                }
                                printf("\n");

                                for (i = 0; i < 16; i++)
                                {
                                    TK[i] = PTK[i + 32];
                                }

                                printf("TK : ");
                                for (i = 0; i < 16; i++)
                                {
                                    printf("%X ", TK[i]);
                                }
                                printf("\n");

                                is_key = 1;
                            }
                        }
                    }
                    else if (is_key == 1)
                    {
                        const unsigned char *datatemp = (const char *)(pkt_data + datalen);
                        int datatemplen = header->len - datalen;
                        datalen = 0;

                        struct tkip *tkipdata;

                        tkipdata = (struct tkip *)(datatemp);
                        datalen += sizeof(*tkipdata);

                        unsigned char ta[IEEE80211_ADDR_LEN];
                        unsigned char tsc[6];

                        for (i = 0; i < IEEE80211_ADDR_LEN; i++)
                        {
                            ta[i] = qosdata->i_addr2[i];
                        }

                        for (i = 0; i < 4; i++)
                        {
                            tsc[i] = tkipdata->tkip[7 - i];
                        }

                        tsc[5] = tkipdata->tkip[0];
                        tsc[4] = tkipdata->tkip[2];

                        uint16_t ppk[6];
                        unsigned char rc4_key[16];

                        ppk[0] = join_bytes(tsc[0], tsc[1]);
                        ppk[1] = join_bytes(tsc[2], tsc[3]);
                        ppk[2] = join_bytes(ta[1], ta[0]);
                        ppk[3] = join_bytes(ta[3], ta[2]);
                        ppk[4] = join_bytes(ta[5], ta[4]);

                        for (i = 0; i < 4; i++)
                        {
                            ppk[0] += sbox(ppk[4] ^ join_bytes(TK[1], TK[0]));
                            ppk[1] += sbox(ppk[0] ^ join_bytes(TK[5], TK[4]));
                            ppk[2] += sbox(ppk[1] ^ join_bytes(TK[9], TK[8]));
                            ppk[3] += sbox(ppk[2] ^ join_bytes(TK[13], TK[12]));
                            ppk[4] += sbox(ppk[3] ^ join_bytes(TK[1], TK[0])) + 2 * i;
                            ppk[0] += sbox(ppk[4] ^ join_bytes(TK[1], TK[0]));
                            ppk[1] += sbox(ppk[0] ^ join_bytes(TK[3], TK[2]));
                            ppk[2] += sbox(ppk[1] ^ join_bytes(TK[7], TK[6]));
                            ppk[3] += sbox(ppk[2] ^ join_bytes(TK[15], TK[14]));
                            ppk[4] += sbox(ppk[3] ^ join_bytes(TK[3], TK[2])) + 2 * i + 1;
                        }

                        //Phase 2, step 1
                        ppk[5] = ppk[4] + join_bytes(tsc[5], tsc[4]);

                        //Phase 2, step 2
                        ppk[0] += sbox(ppk[5] ^ join_bytes(TK[1], TK[0]));
                        ppk[1] += sbox(ppk[0] ^ join_bytes(TK[3], TK[2]));
                        ppk[2] += sbox(ppk[1] ^ join_bytes(TK[5], TK[4]));
                        ppk[3] += sbox(ppk[2] ^ join_bytes(TK[7], TK[6]));
                        ppk[4] += sbox(ppk[3] ^ join_bytes(TK[9], TK[8]));
                        ppk[5] += sbox(ppk[4] ^ join_bytes(TK[11], TK[10]));

                        ppk[0] += rotate(ppk[5] ^ join_bytes(TK[13], TK[12]));
                        ppk[1] += rotate(ppk[0] ^ join_bytes(TK[15], TK[14]));
                        ppk[2] += rotate(ppk[1]);
                        ppk[3] += rotate(ppk[2]);
                        ppk[4] += rotate(ppk[3]);
                        ppk[5] += rotate(ppk[4]);

                        //Phase 2, step 3
                        rc4_key[0] = upper_byte(join_bytes(tsc[5],tsc[4]));
                        rc4_key[1] = (rc4_key[0] | 0x20) & 0x7f;
                        rc4_key[2] = lower_byte(join_bytes(tsc[5],tsc[4]));
                        rc4_key[3] = lower_byte((ppk[5]^join_bytes(TK[1],TK[0]))>>1);
                        rc4_key[4] = lower_byte(ppk[0]);
                        rc4_key[5] = upper_byte(ppk[0]);
                        rc4_key[6] = lower_byte(ppk[1]);
                        rc4_key[7] = upper_byte(ppk[1]);
                        rc4_key[8] = lower_byte(ppk[2]);
                        rc4_key[9] = upper_byte(ppk[2]);
                        rc4_key[10] = lower_byte(ppk[3]);
                        rc4_key[11] = upper_byte(ppk[3]);
                        rc4_key[12] = lower_byte(ppk[4]);
                        rc4_key[13] = upper_byte(ppk[4]);
                        rc4_key[14] = lower_byte(ppk[5]);
                        rc4_key[15] = upper_byte(ppk[5]);

                        RC4_KEY rc4;
                        RC4_set_key(&rc4, 16, rc4_key);

                        int data_size = datatemplen - datalen;
                        unsigned char decryptdata[data_size];
                        RC4(&rc4, data_size, (const unsigned char *)pkt_data + datalen, decryptdata);
                        data_size -= 12;
                    }
                }
            }
        }
    }
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