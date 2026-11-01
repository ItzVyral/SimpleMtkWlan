#!/usr/bin/python3
"""Compile the real TXWI builder and check unicast data is not fixed-rate.

This guards the regression where `type` had already been shifted to the 2-bit
frame type but was compared against the unshifted IEEE80211_FC0_TYPE_DATA
(0x08).  The test was always true, so every data frame got MT_TXD2_FIX_RATE,
MT_TXD6_FIXED_BW and MT_TXD3_BA_DISABLE: lowest legacy rate, 20 MHz and no
TX A-MPDU.
"""
from pathlib import Path
import subprocess

b = Path(__file__).resolve().parents[2]
s = (b / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
a = s.index('void\nmt7921_mac_write_txwi_80211(struct mwx_softc *sc, struct mbuf *m,')
fn = s[a:s.index('\n}\n', a) + 3]

pre = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

#define __packed __attribute__((packed))
#define htole32(x) ((uint32_t)(x))

typedef unsigned int u_int;

struct ieee80211_frame { uint8_t i_fc[2]; uint8_t i_addr1[6]; };
struct ieee80211_frame_min { uint8_t i_fc[2]; uint8_t i_dur[2]; uint8_t i_addr1[6]; };
struct ieee80211_tx_ba { int ba_state; uint16_t ba_params; };
struct ieee80211_node { struct ieee80211_tx_ba ni_tx_ba[8]; };
struct ieee80211_channel { uint32_t ic_freq, ic_flags; };
struct ieee80211com {
	int ic_curmode;
	int ic_flags;
	struct ieee80211_channel ic_channels[256];
};
struct mt76_txwi { uint32_t txwi[8]; };
struct mwx_softc {
	struct ieee80211com sc_ic;
	int8_t sc_tx_amsdu;
	void *sc_drvbpf;
};

struct mbuf { uint8_t buf[128]; size_t len; };
#define mtod(m, t) ((t)((m)->buf))
#define mbuf_len(m) ((size_t)(m)->len)

#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_SHIFT 2
#define IEEE80211_FC0_TYPE_MGT 0x00
#define IEEE80211_FC0_TYPE_CTL 0x04
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_SHIFT 4
#define IEEE80211_FC0_SUBTYPE_ACTION 0xd0
#define IEEE80211_FC0_SUBTYPE_QOS 0x80
#define IEEE80211_QOS_TID 0x000f
#define IEEE80211_BA_AGREED 2
#define IEEE80211_ADDBA_AMSDU 0x0040
#define IEEE80211_CATEG_BA 3
#define IEEE80211_ACTION_ADDBA_REQ 0
#define IEEE80211_IS_MULTICAST(a) (*(a) & 0x01)

#define MT_HDR_FORMAT_802_11 (2 << 16)
#define MT_TXD1_TID_MASK 0x00700000
#define MT_TXD1_TID(x) (((x) << 20) & MT_TXD1_TID_MASK)
#define MT_TXD1_HDR_INFO_MASK 0x0000f800
#define MT_TXD1_HDR_INFO(x) (((x) << 11) & MT_TXD1_HDR_INFO_MASK)
#define MT_TXD2_FIX_RATE (1U << 31)
#define MT_TXD2_HTC_VLD (1U << 13)
#define MT_TXD2_MULTICAST (1U << 10)
#define MT_TXD2_FRAME_TYPE_MASK 0x00000030
#define MT_TXD2_SUB_TYPE_MASK 0x0000000f
#define MT_TXD2_FRAME_TYPE(x) (((x) << 4) & MT_TXD2_FRAME_TYPE_MASK)
#define MT_TXD2_SUB_TYPE(x) ((x) & MT_TXD2_SUB_TYPE_MASK)
#define MT_TXD3_BA_DISABLE (1U << 28)
#define MT_TXD5_ADD_BA (1U << 14)
#define MT_TXD6_TX_RATE_MASK 0x3fff0000
#define MT_TXD6_TX_RATE_SHIFT 16
#define MT_TXD6_FIXED_BW (1U << 2)
#define MT_TXD7_TYPE_MASK 0x00300000
#define MT_TXD7_SUB_TYPE_MASK 0x000f0000
#define MT_TXD7_TYPE(x) (((x) << 20) & MT_TXD7_TYPE_MASK)
#define MT_TXD7_SUB_TYPE(x) (((x) << 16) & MT_TXD7_SUB_TYPE_MASK)
#define MT_TXD7_HW_AMSDU (1U << 10)
#define MT_TX_RATE_IDX_MASK 0x1ff
#define MT_TX_RATE_MODE_SHIFT 9
#define MT_TX_RATE_MODE_MASK 0x600

static inline int
ieee80211_has_qos(const struct ieee80211_frame *wh)
{
	return (wh->i_fc[0] &
	    (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_QOS)) ==
	    (IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS);
}

static inline uint16_t
ieee80211_get_qos(const struct ieee80211_frame *wh)
{
	return *(const uint16_t *)((const uint8_t *)wh + 24);
}

static inline u_int16_t
ieee80211_get_qos_ctl(const struct ieee80211_frame *wh)
{
	return 0;
}

static u_int
ieee80211_get_hdrlen(const struct ieee80211_frame *wh)
{
	uint8_t type = (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) >>
	    IEEE80211_FC0_TYPE_SHIFT;

	return type == (IEEE80211_FC0_TYPE_CTL >> IEEE80211_FC0_TYPE_SHIFT) ?
	    sizeof(struct ieee80211_frame_min) : 24;
}

static uint32_t rate_val_calls;
static uint32_t
mt7921_mac_tx_rate_val(struct mwx_softc *sc)
{
	(void)sc;
	rate_val_calls++;
	return 0x0a;
}

/* Defined next to the function in the real driver. */
static uint32_t mwx_tx_data_cnt, mwx_tx_data_fixed_cnt, mwx_tx_data_noba_cnt;
'''

post = r'''
static void
fill_qos(struct mbuf *m, uint8_t fc0, uint8_t fc1, uint16_t qos,
    int multicast)
{
	struct ieee80211_frame *wh;

	memset(m, 0, sizeof(*m));
	wh = mtod(m, struct ieee80211_frame *);
	wh->i_fc[0] = fc0;
	wh->i_fc[1] = fc1;
	wh->i_addr1[0] = multicast ? 0x01 : 0x02;
	m->len = 24 + 2;
	memcpy(m->buf + 24, &qos, sizeof(qos));
}

int
main(void)
{
	struct mwx_softc sc = {};
	struct ieee80211_node ni = {};
	struct mbuf m = {};
	struct mt76_txwi tx = {};

	/* 1: QoS data, unicast, no BA agreement yet. */
	fill_qos(&m, IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS, 0,
	    5, 0);
	memset(&tx, 0, sizeof(tx));
	mt7921_mac_write_txwi_80211(&sc, &m, &ni, &tx);
	assert((tx.txwi[2] & MT_TXD2_FIX_RATE) == 0);	/* the bug */
	assert((tx.txwi[6] & MT_TXD6_FIXED_BW) == 0);	/* the bug */
	assert((tx.txwi[2] & MT_TXD2_HTC_VLD) == 0);
	assert((tx.txwi[3] & MT_TXD3_BA_DISABLE) != 0);	/* no BA yet: correct */
	assert(rate_val_calls == 0);
	assert((tx.txwi[1] & MT_TXD1_TID_MASK) >> 20 == 5);
	assert((tx.txwi[2] & MT_TXD2_FRAME_TYPE_MASK) >> 4 == 2);
	assert((tx.txwi[2] & MT_TXD2_MULTICAST) == 0);
	assert((tx.txwi[7] & MT_TXD7_TYPE_MASK) >> 20 == 2);
	assert(mwx_tx_data_cnt == 1 && mwx_tx_data_fixed_cnt == 0);
	assert(mwx_tx_data_noba_cnt == 1);

	/* 2: QoS data, unicast, BA agreed and A-MSDU allowed. */
	ni.ni_tx_ba[5].ba_state = IEEE80211_BA_AGREED;
	ni.ni_tx_ba[5].ba_params = IEEE80211_ADDBA_AMSDU;
	sc.sc_tx_amsdu = 1;
	memset(&tx, 0, sizeof(tx));
	mt7921_mac_write_txwi_80211(&sc, &m, &ni, &tx);
	assert((tx.txwi[2] & MT_TXD2_FIX_RATE) == 0);
	assert((tx.txwi[6] & MT_TXD6_FIXED_BW) == 0);
	assert((tx.txwi[3] & MT_TXD3_BA_DISABLE) == 0);
	assert((tx.txwi[7] & MT_TXD7_HW_AMSDU) != 0);
	assert(rate_val_calls == 0);
	assert(mwx_tx_data_noba_cnt == 1);	/* unchanged */

	/* 3: multicast data must still be fixed-rate. */
	fill_qos(&m, IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS, 0,
	    0, 1);
	memset(&tx, 0, sizeof(tx));
	mt7921_mac_write_txwi_80211(&sc, &m, &ni, &tx);
	assert((tx.txwi[2] & MT_TXD2_FIX_RATE) != 0);
	assert((tx.txwi[2] & MT_TXD2_HTC_VLD) != 0);
	assert((tx.txwi[2] & MT_TXD2_MULTICAST) != 0);
	assert((tx.txwi[6] & MT_TXD6_FIXED_BW) != 0);
	assert(((tx.txwi[6] & MT_TXD6_TX_RATE_MASK) >> 16) == 0x0a);
	assert((tx.txwi[3] & MT_TXD3_BA_DISABLE) != 0);
	assert(rate_val_calls == 1);

	/* 4: management frames must still be fixed-rate. */
	fill_qos(&m, IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ACTION, 0,
	    0, 0);
	m.len = 24;
	memset(&tx, 0, sizeof(tx));
	mt7921_mac_write_txwi_80211(&sc, &m, &ni, &tx);
	assert((tx.txwi[2] & MT_TXD2_FIX_RATE) != 0);
	assert((tx.txwi[2] & MT_TXD2_HTC_VLD) != 0);
	assert((tx.txwi[6] & MT_TXD6_FIXED_BW) != 0);
	assert((tx.txwi[3] & MT_TXD3_BA_DISABLE) != 0);
	assert(rate_val_calls == 2);
	assert(mwx_tx_data_cnt == 2);	/* only unicast data counted */

	/* 5: control frames use the 10-byte header length. */
	memset(&m, 0, sizeof(m));
	m.len = 10;
	m.buf[0] = IEEE80211_FC0_TYPE_CTL;
	memset(&tx, 0, sizeof(tx));
	mt7921_mac_write_txwi_80211(&sc, &m, &ni, &tx);
	assert(((tx.txwi[1] & MT_TXD1_HDR_INFO_MASK) >> 11) ==
	    sizeof(struct ieee80211_frame_min) / 2);
	assert((tx.txwi[2] & MT_TXD2_FIX_RATE) != 0);

	puts("PASS actual TXWI builder: unicast data keeps firmware rate control, "
	    "full bandwidth and A-MPDU (BA_DISABLE only before ADDBA); "
	    "multicast/mgmt/control stay fixed-rate.");
}
'''

p = b / 'tests/tx-rate/test-txwi.cpp'
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(pre + '\n' + fn + '\n' + post)
subprocess.run(['clang++', '-std=c++14', '-fsanitize=address,undefined',
    str(p), '-o', str(p.with_suffix(''))], check=True)
r = subprocess.run([str(p.with_suffix(''))], capture_output=True, text=True)
(b / 'tests/tx-rate/txwi-result.txt').write_text(r.stdout + r.stderr)
print(r.stdout + r.stderr)
r.check_returncode()
