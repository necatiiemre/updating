// test_starter — wait for the "start-test" trigger packet before CMC tests run.
//
// Listens on a kernel interface (default: ens1f0np0) for a single packet
// matching the same wire encoding used by dpdk_cmc MMMS:
//
//   Ethernet (dst MAC bytes [4..5] = VL-IDX) + 802.1Q VLAN + IPv4 + UDP
//   - VLAN ID  : 225
//   - VL-IDX   : 8009
//   - Payload  : 101 B, "start-test" + zero pad + last byte = seq number
//
// Exit contract for the MainSoftware orchestrator:
//   stdout "TEST_STARTER_RESULT=OK"      packet matched within timeout
//   stdout "TEST_STARTER_RESULT=TIMEOUT" no matching packet seen
//   stdout "TEST_STARTER_RESULT=ERROR"   socket / interface failure
// Process always exits 0 so the SSH wrapper can read the result line.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define EXPECTED_VLAN        225
#define EXPECTED_VL_IDX      8009
#define EXPECTED_PAYLOAD     "start-test"
#define EXPECTED_PAYLOAD_LEN 101
#define DEFAULT_IFACE        "ens1f0np0"
#define DEFAULT_TIMEOUT_S    300

struct vlan_hdr_be {
    uint16_t tci;
    uint16_t inner_proto;
} __attribute__((packed));

static int open_listener(const char *ifname)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(s);
        return -1;
    }
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(s);
        return -1;
    }

    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        perror("PACKET_ADD_MEMBERSHIP (non-fatal)");
    }

    int aux_on = 1;
    if (setsockopt(s, SOL_PACKET, PACKET_AUXDATA,
                   &aux_on, sizeof(aux_on)) < 0) {
        perror("PACKET_AUXDATA (non-fatal)");
    }
    return s;
}

typedef enum {
    CLASSIFY_IGNORE      = 0,  /* not VLAN 225 / VL-IDX 8009 — not for us */
    CLASSIFY_MATCH       = 1,  /* exact trigger packet */
    CLASSIFY_UNEXPECTED  = 2,  /* VLAN+VL-IDX match, payload does not */
} classify_t;

static classify_t classify_packet(const uint8_t *frame, size_t len,
                                  uint16_t aux_vlan, bool aux_vlan_valid)
{
    if (len < sizeof(struct ether_header)) {
        return CLASSIFY_IGNORE;
    }
    const struct ether_header *eh = (const struct ether_header *)frame;

    uint16_t vl_idx = ((uint16_t)eh->ether_dhost[4] << 8) | eh->ether_dhost[5];
    if (vl_idx != EXPECTED_VL_IDX) {
        return CLASSIFY_IGNORE;
    }

    uint16_t vlan_id;
    const uint8_t *l3;
    size_t        l3_len;

    uint16_t ether_type = ntohs(eh->ether_type);
    if (ether_type == ETH_P_8021Q) {
        if (len < sizeof(struct ether_header) + sizeof(struct vlan_hdr_be)) {
            return CLASSIFY_IGNORE;
        }
        const struct vlan_hdr_be *vh = (const struct vlan_hdr_be *)
            (frame + sizeof(struct ether_header));
        vlan_id = ntohs(vh->tci) & 0x0FFF;
        if (ntohs(vh->inner_proto) != ETH_P_IP) {
            return CLASSIFY_IGNORE;
        }
        l3     = (const uint8_t *)vh + sizeof(struct vlan_hdr_be);
        l3_len = len - sizeof(struct ether_header) - sizeof(struct vlan_hdr_be);
    } else if (aux_vlan_valid) {
        // Hardware-stripped VLAN — tag was lifted into tpacket_auxdata.
        vlan_id = aux_vlan & 0x0FFF;
        if (ether_type != ETH_P_IP) {
            return CLASSIFY_IGNORE;
        }
        l3     = frame + sizeof(struct ether_header);
        l3_len = len - sizeof(struct ether_header);
    } else {
        return CLASSIFY_IGNORE;
    }

    if (vlan_id != EXPECTED_VLAN) {
        return CLASSIFY_IGNORE;
    }

    // From here on the VLAN+VL-IDX both match — anything that fails below
    // is "addressed to us but not the expected trigger", which the operator
    // wants to see in the log.
    if (l3_len < 20 + 8) {
        return CLASSIFY_UNEXPECTED;
    }
    const uint8_t *ip  = l3;
    int            ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || (size_t)ihl + 8 > l3_len) {
        return CLASSIFY_UNEXPECTED;
    }
    if (ip[9] != IPPROTO_UDP) {
        return CLASSIFY_UNEXPECTED;
    }

    const uint8_t *payload     = ip + ihl + 8;
    size_t         payload_len = l3_len - (size_t)ihl - 8;

    if (payload_len < EXPECTED_PAYLOAD_LEN) {
        return CLASSIFY_UNEXPECTED;
    }
    if (memcmp(payload, EXPECTED_PAYLOAD, strlen(EXPECTED_PAYLOAD)) != 0) {
        return CLASSIFY_UNEXPECTED;
    }
    return CLASSIFY_MATCH;
}

int main(int argc, char **argv)
{
    const char *iface     = DEFAULT_IFACE;
    int         timeout_s = DEFAULT_TIMEOUT_S;

    static struct option opts[] = {
        {"interface", required_argument, 0, 'i'},
        {"timeout",   required_argument, 0, 't'},
        {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "i:t:", opts, NULL)) != -1) {
        switch (c) {
        case 'i':
            iface = optarg;
            break;
        case 't': {
            int v = atoi(optarg);
            if (v > 0) timeout_s = v;
            break;
        }
        default:
            fprintf(stderr, "usage: %s [--interface=<dev>] [--timeout=<sec>]\n",
                    argv[0]);
            return 1;
        }
    }

    printf("test_starter: listening on %s for VLAN=%u VL-IDX=%u 'start-test' "
           "(timeout %ds)\n",
           iface, EXPECTED_VLAN, EXPECTED_VL_IDX, timeout_s);
    fflush(stdout);

    int s = open_listener(iface);
    if (s < 0) {
        printf("TEST_STARTER_RESULT=ERROR\n");
        fflush(stdout);
        return 0;
    }

    struct pollfd pfd      = { .fd = s, .events = POLLIN };
    time_t        deadline = time(NULL) + timeout_s;
    uint64_t      unexpected_count = 0;

    while (1) {
        time_t now = time(NULL);
        if (now >= deadline) {
            // Promiscuous capture on this interface keeps poll() satisfied
            // with unrelated traffic, so we have to gate on the deadline
            // ourselves — relying solely on poll's own timeout never
            // returns pr == 0 when packets are continuously arriving.
            close(s);
            printf("TEST_STARTER_RESULT=TIMEOUT\n");
            fflush(stdout);
            return 0;
        }
        int wait_ms = (int)((deadline - now) * 1000);
        int pr      = poll(&pfd, 1, wait_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            close(s);
            printf("TEST_STARTER_RESULT=ERROR\n");
            fflush(stdout);
            return 0;
        }
        if (pr == 0) {
            // poll's own timeout fired (no traffic at all).
            continue;
        }

        uint8_t      buf[2048];
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        char         ctl[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
        struct msghdr mh = {
            .msg_name       = NULL,
            .msg_namelen    = 0,
            .msg_iov        = &iov,
            .msg_iovlen     = 1,
            .msg_control    = ctl,
            .msg_controllen = sizeof(ctl),
            .msg_flags      = 0,
        };
        ssize_t n = recvmsg(s, &mh, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvmsg");
            continue;
        }

        bool     aux_valid = false;
        uint16_t aux_vlan  = 0;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
             cm != NULL;
             cm = CMSG_NXTHDR(&mh, cm)) {
            if (cm->cmsg_level == SOL_PACKET &&
                cm->cmsg_type  == PACKET_AUXDATA) {
                struct tpacket_auxdata aux;
                memcpy(&aux, CMSG_DATA(cm), sizeof(aux));
                if (aux.tp_status & TP_STATUS_VLAN_VALID) {
                    aux_valid = true;
                    aux_vlan  = aux.tp_vlan_tci;
                }
            }
        }

        classify_t cls = classify_packet(buf, (size_t)n, aux_vlan, aux_valid);
        if (cls == CLASSIFY_MATCH) {
            close(s);
            printf("TEST_STARTER_RESULT=OK\n");
            fflush(stdout);
            return 0;
        }
        if (cls == CLASSIFY_UNEXPECTED) {
            unexpected_count++;
            printf("test_starter: unexpected packet on VLAN=%u VL-IDX=%u "
                   "(len=%zd, count=%llu) — ignoring\n",
                   EXPECTED_VLAN, EXPECTED_VL_IDX, n,
                   (unsigned long long)unexpected_count);
            fflush(stdout);
        }
    }
}
