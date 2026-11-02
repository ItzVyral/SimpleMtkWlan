#!/usr/bin/python3
"""Check the firmware WTBL Block Ack request built by mwx_mcu_sta_wtbl_ba().

Linux mt76 programs the BA state in two MCU messages: a WTBL_SET request with
a nested WTBL_BA TLV, then a STA_REC_BA record.  Sending only the latter (what
this driver used to do) leaves the WTBL without BA state, so the MAC keeps
sending single MPDUs and never answers the AP's A-MPDUs as a recipient.

This test compiles the real function with stub mbuf/MCU helpers and verifies:
  - the STA_REC_WTBL TLV wraps the nested WTBL_BA TLV and advertises tlv_num=1,
  - originator fields: sn / ba_en / ba_winsize,
  - recipient fields: peer_addr / rst_ba_tid / rst_ba_sel / rst_ba_sb,
  - disable clears sn / ba_en / ba_winsize.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
src = Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp'
s = src.read_text()
a = s.index('static int\nmwx_mcu_sta_wtbl_ba(')
fn = s[a:s.index('\n}\n', a) + 3]

pre = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

#define __packed __attribute__((packed))
#define htole16(x) ((uint16_t)(x))
#define le16toh(x) ((uint16_t)(x))
typedef unsigned int u_int;

#define IEEE80211_ADDR_LEN 6
#define STA_REC_WTBL 0x0d
#define WTBL_SET 2
#define WTBL_BA 0x08
#define MT_BA_TYPE_ORIGINATOR 1
#define MT_BA_TYPE_RECIPIENT 2
#define RST_BA_MAC_TID_MATCH 0

struct ieee80211_node { uint8_t ni_macaddr[IEEE80211_ADDR_LEN]; };
struct mwx_node { struct ieee80211_node ni; uint16_t wcid; };
struct mwx_vif { uint8_t idx; uint8_t omac_idx; uint8_t band_idx; uint8_t wmm_idx; };
struct mwx_softc { struct mwx_vif sc_vif; };

struct sta_req_hdr {
	uint8_t bss_idx, wlan_idx_lo;
	uint16_t tlv_num;
	uint8_t is_tlv_append, muar_idx, wlan_idx_hi, rsv;
} __packed;

struct sta_rec_wtbl {
	uint16_t tag, len;
	uint8_t wlan_idx_lo, operation;
	uint16_t tlv_num;
	uint8_t wlan_idx_hi, rsv[3];
} __packed;

struct wtbl_ba {
	uint16_t tag, len;
	uint8_t tid, ba_type, rsv0[2];
	uint16_t sn;
	uint8_t ba_en, ba_winsize_idx;
	uint16_t ba_winsize;
	uint8_t peer_addr[IEEE80211_ADDR_LEN];
	uint8_t rst_ba_tid, rst_ba_sel, rst_ba_sb, band_idx;
	uint8_t rsv1[4];
} __packed;

struct mbuf { uint8_t buf[1024]; size_t len; };

#define MWX_DEV_LOG(...) do {} while (0)
#define ENOBUFS 12
static struct mbuf stored;

static struct mbuf *mwx_alloc_sta_req_tlv(int) {
	auto m = new mbuf{};
	m->len = 0;
	return m;
}

void *mwx_append_len(struct mbuf *m, int len) {
	assert(m->len + (size_t)len <= sizeof(m->buf));
	void *p = m->buf + m->len;
	memset(p, 0, len);
	m->len += len;
	return p;
}

void *mwx_append_tlv(struct mbuf *m, uint16_t *tlvnum, int tag, int len) {
	void *p = mwx_append_len(m, len);
	uint16_t hdr[2] = { htole16((uint16_t)tag), htole16((uint16_t)len) };
	memcpy(p, hdr, sizeof(hdr));
	(*tlvnum)++;
	return p;
}

struct mbuf *mwx_fill_sta_req_hdr(struct mbuf *m, struct mwx_vif *mvif,
    uint8_t muar_idx, uint16_t wcid, uint16_t tlvnum) {
	assert(m->len + sizeof(struct sta_req_hdr) <= sizeof(m->buf));
	memmove(m->buf + sizeof(struct sta_req_hdr), m->buf, m->len);
	struct sta_req_hdr *h = (struct sta_req_hdr *)m->buf;
	memset(h, 0, sizeof(*h));
	h->bss_idx = mvif->idx;
	h->wlan_idx_lo = wcid & 0xff;
	h->wlan_idx_hi = wcid >> 8;
	h->muar_idx = muar_idx;
	h->is_tlv_append = 1;
	h->tlv_num = htole16(tlvnum);
	m->len += sizeof(*h);
	return m;
}

#define MCU_UNI_CMD_STA_REC_UPDATE 0x80020005
int mwx_mcu_send_mbuf(struct mwx_softc *, uint32_t, struct mbuf *m, int *) {
	memcpy(stored.buf, m->buf, m->len);
	stored.len = m->len;
	delete m;
	return 0;
}

static int mwx_mcu_sta_wtbl_ba(struct mwx_softc *, struct ieee80211_node *,
    uint8_t, uint16_t, uint16_t, int, int);

static void dump(const char *tag) {
	printf("%s len=%zu:", tag, stored.len);
	for (size_t i = 0; i < stored.len; i++)
		printf(" %02x", stored.buf[i]);
	printf("\n");
}

static void check_common(uint8_t tid, uint16_t wcid) {
	auto h = (struct sta_req_hdr *)stored.buf;
	auto wtbl = (struct sta_rec_wtbl *)(stored.buf + sizeof(*h));
	auto ba = (struct wtbl_ba *)((uint8_t *)wtbl + sizeof(*wtbl));

	assert(stored.len == sizeof(*h) + sizeof(*wtbl) + sizeof(*ba));
	assert(h->tlv_num == htole16(1));
	assert(h->wlan_idx_lo == (wcid & 0xff));
	assert(h->wlan_idx_hi == (wcid >> 8));
	assert(wtbl->tag == htole16(STA_REC_WTBL));
	assert(wtbl->len == htole16(sizeof(*wtbl) + sizeof(*ba)));
	assert(wtbl->wlan_idx_lo == (wcid & 0xff));
	assert(wtbl->wlan_idx_hi == (wcid >> 8));
	assert(wtbl->operation == WTBL_SET);
	assert(wtbl->tlv_num == htole16(1));
	assert(ba->tag == htole16(WTBL_BA));
	assert(ba->len == htole16(sizeof(*ba)));
	assert(ba->tid == tid);
}

int main(void) {
	struct mwx_softc sc = {};
	sc.sc_vif.idx = 2;
	sc.sc_vif.omac_idx = 3;
	const uint8_t peer[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
	struct mwx_node mn = {};
	mn.wcid = 0x105;
	memcpy(mn.ni.ni_macaddr, peer, sizeof(peer));
	int rv;

	/* TX originator, enabled. */
	rv = mwx_mcu_sta_wtbl_ba(&sc, (struct ieee80211_node *)&mn, 3,
	    0x123, 64, 1, 1);
	assert(rv == 0);
	check_common(3, 0x105);
	{
		struct wtbl_ba *ba = (struct wtbl_ba *)(stored.buf + stored.len - sizeof(*ba));
		assert(ba->ba_type == MT_BA_TYPE_ORIGINATOR);
		assert(ba->sn == htole16(0x123));
		assert(ba->ba_en == 1);
		assert(ba->ba_winsize == htole16(64));
	}

	/* RX recipient, enabled. */
	rv = mwx_mcu_sta_wtbl_ba(&sc, (struct ieee80211_node *)&mn, 5,
	    0x456, 64, 1, 0);
	assert(rv == 0);
	check_common(5, 0x105);
	{
		struct wtbl_ba *ba = (struct wtbl_ba *)(stored.buf + stored.len - sizeof(*ba));
		assert(ba->ba_type == MT_BA_TYPE_RECIPIENT);
		assert(memcmp(ba->peer_addr, peer, sizeof(peer)) == 0);
		assert(ba->rst_ba_tid == 5);
		assert(ba->rst_ba_sel == RST_BA_MAC_TID_MATCH);
		assert(ba->rst_ba_sb == 1);
		assert(ba->ba_winsize == htole16(64));
	}

	/* TX originator, disabled: all session fields cleared. */
	rv = mwx_mcu_sta_wtbl_ba(&sc, (struct ieee80211_node *)&mn, 3,
	    0x123, 64, 0, 1);
	assert(rv == 0);
	{
		struct wtbl_ba *ba = (struct wtbl_ba *)(stored.buf + stored.len - sizeof(*ba));
		assert(ba->ba_type == MT_BA_TYPE_ORIGINATOR);
		assert(ba->sn == 0);
		assert(ba->ba_en == 0);
		assert(ba->ba_winsize == 0);
	}

	puts("PASS: WTBL_SET request wraps WTBL_BA with Linux-compatible "
	    "originator/recipient fields (real driver function, ASan/UBSan).");
	return 0;
}
'''
tmp = tempfile.TemporaryDirectory(prefix='mtk-ba-test-')
art = Path(tmp.name)
cpp = art / 'ba-test.cpp'
exe = art / 'ba-test'
cpp.write_text(pre + fn)
subprocess.run(['clang++', '-std=c++14', '-fsanitize=address,undefined',
                '-g', str(cpp), '-o', str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
