# CODECS.md

Complete reference for all BLE advertisement codec families in `ha-ble-adv`. Ported C++ implementation covers only the FanLamp family; all others are Python-only (Home Assistant integration).

Source: `ha-ble-adv/custom_components/ble_adv/codecs/`

---

## Architecture

All codecs inherit from `BleAdvCodec` (abstract base in `models.py`). Each implements four transforms:

```
decrypt(buffer) → decoded bytes | None     # raw payload → plaintext
encrypt(decoded) → buffer bytes            # plaintext → raw payload
convert_to_enc(decoded) → BleAdvEncCmd     # plaintext → command struct
convert_from_enc(enc_cmd) → decoded bytes  # command struct → plaintext
```

The orchestration layer (`decode_adv` / `encode_advs`) handles header stripping, prefix validation, counter management, and seed generation.

**Common configuration fields:**

| Field | Meaning |
|-------|---------|
| `_len` | Encrypted payload size (bytes, excluding header/footer) |
| `_tx_step` | Amount added to `tx_count` per encode |
| `_tx_max` | `tx_count` wraps modulo this |
| `_seed_max` | Random seed upper bound (0 = no seed) |
| `_header` | Header bytes verified/reinserted at `_header_start_pos` |
| `_prefix` | Prefix verified/stripped after decrypt, prepended before encrypt |
| `_footer` | Footer appended after encrypted payload |
| `_ble_type` | BLE AD type byte (0x03, 0x05, 0x07, 0x16, 0xFF) |
| `_ad_flag` | AD Flags byte prepended when non-zero |

**Translator system:** `Trans` objects map HA entity attributes ↔ command bytes.
- `copy(attr, dest, factor)` — linear scaling: `raw = attr × factor`
- `split_copy(attr, [dests], factor, mod)` — split across args with modulo
- `.no_direct()` / `.no_reverse()` — one-direction only

---

## Codec Tree

```
BleAdvCodec (abstract)
│
├── FanLampEncoder
│   ├── FanLampEncoderV1Base
│   │   ├── FanLampEncoderV1          → fanlamp_pro_v1, lampsmart_pro_v1, + remotes
│   │   │   └── FanLampEncoderV1aa   → lampsmart_pro_vi1, other_v1a/b
│   │   ├── FanLampEncoderV1R0       → fanlamp_pro_v1/r0
│   │   └── FanLampEncoderV1R1       → fanlamp_pro_v1/r1
│   └── FanLampEncoderV2             → fanlamp_pro_v2/v3, lampsmart_pro_v2/v3, remotes
│
├── ZhijiaEncoder
│   ├── ZhijiaEncoderV0              → zhijia_v0, zhiguang_v0
│   ├── ZhijiaEncoderV1              → zhijia_v1, zhiguang_v1
│   │   ├── ZhijiaEncoderV2          → zhijia_v2, zhiguang_v2
│   │   └── ZhijiaEncoderRemote      → zhijia_vr1
│
├── ZhimeiEncoderV0                  → zhimei_fan_v0, zhimei_fan_vr0
├── ZhimeiEncoderV1                  → zhimei_fan_v1, zhimei_v1, + remotes
├── ZhimeiEncoderV2                  → zhimei_v2
│
├── AgarceEncoder                    → agarce_v3, agarce_v4
├── MantraEncoder                    → mantra_v0, mantra_v1, + iOS variants
│
├── RuiXinEncoder                    → ruixin_v0
│   └── RuiXinRemoteEncoder          → ruixin_v0/r1
│
├── SmartElfinEncoder                → smartelfin_v0
├── LeEncoder                        → lelight
├── RwEncoder                        → rwlight_mix, rwlight_mix/ios
└── RemoteEncoder                    → remote_v4
```

---

## 1. FanLamp / LampSmart Pro

**App:** FanLamp Pro (Android/iOS), LampSmart Pro (Android/iOS)  
**Source:** `fanlamp.py`

Common CRC helper: `_crc16(buf, seed)` = CRC16-CCITT (poly=0x1021, matches Python `binascii.crc_hqx`).  
All variants: `_len = 24` base, `_tx_max = 125`.

---

### 1.1 FanLampEncoderV1Base

Crypto core shared by V1, V1R0, V1R1, V1aa.

**Encrypt:**
1. Append CRC2 = `crc16(buf, 0xA5BE)` (or forced value) as LE16
2. `reverse_all()`
3. `whiten(seed=0x0C)`

**Decrypt:**
1. `whiten(seed=0x0C)`
2. `reverse_all()`
3. Verify last 2 bytes = CRC2

**Header override:** Appends `whiten(reverse_all(PREFIX), 0x6F)` to caller-supplied bytes, subtracts `len(PREFIX)` from `_len` so total on-wire stays constant.

```
PREFIX = [0xAA, 0x98, 0x43, 0xAF, 0x0B, 0x46, 0x46, 0x46]
```

---

### 1.2 FanLampEncoderV1

Adds inner CRC16 + seed validation on top of V1Base.

**Parameters:** `arg2` (fixed byte injected per codec), `arg2_only_on_pair` (bool), `xor1` (bool)

**Decoded payload layout (14 bytes after CRC2 strip):**

| Bytes | Field |
|-------|-------|
| [0] | `cmd` |
| [1:3] | `group_index` LE16 → `index = bits[11:8]`, `id = bits[15:12]∣[7:0]` |
| [3] | `arg0` (or `id & 0xFF` on pair) |
| [4] | `arg1` (or `(id>>8) & 0xF0` on pair) |
| [5] | `arg2` (validated by `_get_arg2`) |
| [6] | `tx_count` |
| [7] | `param` |
| [8] | `seed8 ^ id_high_byte` (or `seed8^1` if `xor1`) |
| [9] | `seed8` (or `seed8^1` if `xor1`) |
| [10:12] | `seed` BE |
| [12:14] | inner CRC16-CCITT |

**`_get_arg2(cmd, enc_arg2)` logic:**
```
cmd == 0x22  → return enc_arg2 (RGB passthrough)
cmd == 0x28  → return _arg2 (pair always injects)
!arg2_only_on_pair && cmd ∉ {0x12,0x13,0x1E,0x1F} → return _arg2
otherwise → return 0
```

**V1 device variants:**

| ID | `_arg2` | `arg2_only_on_pair` | `xor1` | `forced_crc2` | Header | BLE type | ad_flag |
|----|---------|---------------------|--------|---------------|--------|----------|---------|
| `fanlamp_pro_v1` | 0x83 | False | False | — | `[0x77, 0xF8]` | 0x03 | 0x19 |
| `lampsmart_pro_v1` | 0x81 | True | False | — | `[0x77, 0xF8]` | 0x03 | 0x19 |
| `remote_v1` | 0x83 | False | True | 0x9372 | `[0x56, 0x55, 0x18, 0x87, 0x52]` | 0xFF | 0x00 |
| `fanlamp_pro_v1/r3` | 0x83 | False | True | 0x9372 | `[0x55, 0x55, 0x18, 0x87, 0x52]` | 0xFF | 0x00 |
| `other_v1a` | 0x81 | True | True | — | `[0x77, 0xF8]` | 0x03 | 0x02 |
| `lampsmart_pro_v1/r1` | 0x00 | False | True | 0x9372 | `[0x62, 0x55, 0x18, 0x87, 0x52]` | 0xFF | 0x00 |

---

### 1.3 FanLampEncoderV1aa

Subclass of V1 with different whitening seed and trailer byte instead of CRC2.

**Extended PREFIX (9 bytes):** `[0x55, 0xAA, 0x98, 0x43, 0xAF, 0x0B, 0x46, 0x46, 0x46]`

**Encrypt:**
1. Append `0xAA`
2. `reverse_all()`
3. `whiten(seed=0x2B)` ← different seed from V1Base

**Decrypt:**
1. `whiten(seed=0x2B)`
2. `reverse_all()`
3. Verify `decoded[-1] == 0xAA`, strip it

| ID | `_arg2` | `arg2_only_on_pair` | `xor1` | Header | BLE type | ad_flag |
|----|---------|---------------------|--------|--------|----------|---------|
| `lampsmart_pro_vi1` | 0x81 | True | False | `[0xF9, 0x08]` | 0x03 | 0x19 |
| `other_v1b` | 0x81 | True | True | `[0xF9, 0x08]` | 0x16 | 0x02 |

---

### 1.4 FanLampEncoderV1R0

Simplified variant: V1Base crypto without inner CRC16 or seed logic.

**Decoded payload layout (14 bytes):**

| Bytes | Field |
|-------|-------|
| [0] | `cmd` |
| [1:3] | `group_index` → `index` / `id` |
| [3] | `arg0` |
| [4] | `arg1` |
| [5] | `arg2` |
| [6] | `arg3` |
| [7] | `param` |
| [8:14] | trailers |

**Trailer encoding:**
- `_null_trailers=False`: `[0x02/0x05, 0x00, 0x00, 0x00, 0x01/0x02, 0x00]` based on `arg2`/`arg3`
- `_null_trailers=True` (V1R1): `[0x00]*6`

| ID | `_null_trailers` | `forced_crc2` | Header | BLE type | ad_flag |
|----|-----------------|---------------|--------|----------|---------|
| `fanlamp_pro_v1/r0` | False | — | `[0xF0, 0xFF]` | 0xFF | 0x19 |
| `fanlamp_pro_v1/r1` | True | 0x0000 | `[0xF0, 0xFF]` | 0xFF | 0x19 |

---

### 1.5 FanLampEncoderV2

XBOXES whiten + optional AES-ECB sign + CRC16-CCITT.

**Parameters:** `device_type` (LE16 embedded in payload), `with_sign` (bool, enables AES authentication for V3)

**XBOXES (128-entry S-box):** Indexed by `((seed + i + 9) & 0x1F) + salt` where `salt = (prefix[1] & 0x3) << 5`

**AES key (for sign):** `[seed_lo, seed_hi, tx_count, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]`

**Encrypt:**
1. Extract seed from `decoded[-2:]` (LE16)
2. Compute sign: `AES-ECB(key, decoded[1:17])[0:2]` (LE16), substituting 0xFFFF if 0; append as LE16
3. Append `0x00` (reserved)
4. Whiten `[2:]` in-place using XBOXES
5. Append seed LE16
6. Append `CRC16-CCITT(buf[0:22], seed ^ 0xFFFF)` LE16

**Decrypt:**
1. Extract `seed` from `buf[20:22]`
2. Verify `CRC16-CCITT(buf[0:22], seed ^ 0xFFFF) == buf[22:24]`
3. Unwhiten `buf[2:19]` (same function, symmetric)
4. Verify sign (if `with_sign`) or verify `sign == 0`
5. Return `decoded[0:17] + buf[20:22]` (seed artificially appended)

**Decoded payload layout (16 bytes after 3-byte prefix strip, + 2 seed bytes):**

| Bytes | Field |
|-------|-------|
| [0] | `tx_count` |
| [1:3] | `device_type` LE16 |
| [3:7] | `id` LE32 |
| [7] | `index` |
| [8] | `cmd` |
| [9] | `0x00` (reserved) |
| [10] | `param` |
| [11] | `arg0` |
| [12] | `arg1` |
| [13] | `arg2` |
| [14:16] | `seed` LE16 (appended during decrypt) |

**Device type values:** `0x0400` = FanLamp Pro, `0x0100` = LampSmart Pro

**FanLamp Pro V2 variants:**

| ID | `device_type` | `with_sign` | Prefix | Header | BLE type | ad_flag |
|----|--------------|-------------|--------|--------|----------|---------|
| `fanlamp_pro_v2` | 0x0400 | False | `[0x10, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_v3` | 0x0400 | True | `[0x20, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_v3/s1` | 0x0400 | True | `[0x20, 0x81, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_v3/s2` | 0x0400 | True | `[0x20, 0x82, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_v3/s3` | 0x0400 | True | `[0x20, 0x83, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_vi3` | 0x0400 | True | `[0x30, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_vi3/s1` | 0x0400 | True | `[0x30, 0x81, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_vi3/s2` | 0x0400 | True | `[0x30, 0x82, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `fanlamp_pro_vi3/s3` | 0x0400 | True | `[0x30, 0x83, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `remote_v2` | 0x0400 | False | `[0x10, 0x00, 0x56]` | `[0xF0, 0x08]` | 0x16 | 0x02 |
| `remote_v3` | 0x0400 | True | `[0x10, 0x00, 0x56]` | `[0xF0, 0x08]` | 0x16 | 0x02 |
| `fanlamp_pro_v3/r3` | 0x0400 | True | `[0x10, 0x00, 0x55]` | `[0xF0, 0x08]` | 0x16 | 0x02 |
| `fanlamp_pro_v3/se` | 0x0400 | True | `[0x10, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |

**LampSmart Pro V2 variants:**

| ID | `device_type` | `with_sign` | Prefix | Header | BLE type | ad_flag |
|----|--------------|-------------|--------|--------|----------|---------|
| `lampsmart_pro_v2` | 0x0100 | False | `[0x10, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `lampsmart_pro_v3` | 0x0100 | True | `[0x30, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `lampsmart_pro_v3/s0_1` | 0x0100 | True | `[0x21, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `lampsmart_pro_v3/s1` | 0x0100 | True | `[0x20, 0x81, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `lampsmart_pro_v3/s2` | 0x0100 | True | `[0x20, 0x82, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `lampsmart_pro_v3/s3` | 0x0100 | True | `[0x20, 0x83, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `lampsmart_pro_vi3` | 0x0100 | True | `[0x21, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x03 | 0x19 |
| `lampsmart_pro_v2/r1` | 0x0100 | False | `[0x10, 0x00, 0x62]` | `[0xF0, 0x08]` | 0x16 | 0x02 |
| `lampsmart_pro_v3/r1` | 0x0100 | True | `[0x10, 0x00, 0x62]` | `[0xF0, 0x08]` | 0x16 | 0x02 |
| `other_v2` | 0x0100 | False | `[0x10, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x16 | 0x19 |
| `other_v3` | 0x0100 | True | `[0x10, 0x80, 0x00]` | `[0xF0, 0x08]` | 0x16 | 0x19 |
| `remote_v21` | 0x0100 | False | `[0x10, 0x00, 0x56]` | `[0xF0, 0x08]` | 0x16 | 0x02 |
| `remote_v31` | 0x0100 | True | `[0x10, 0x00, 0x56]` | `[0xF0, 0x08]` | 0x16 | 0x02 |

---

### 1.6 FanLamp Command Table

Applies to both V1 and V2. Arg layout differs between V1 and V2 for `0x21`.

#### Light commands

| cmd | Action | V1 args | V2 args |
|-----|--------|---------|---------|
| `0x10` | Main light ON | — | — |
| `0x11` | Main light OFF | — | — |
| `0x12` | Second light ON | — | — |
| `0x13` | Second light OFF | — | — |
| `0x09` | Light toggle | (remote only) | (remote only) |
| `0x21` | CT brightness | `param=flag, arg0=cold×255, arg1=warm×255` | `arg0=flag, arg1=cold×255, arg2=warm×255` |
| `0x22` | RGB color | `arg0=R×255, arg1=G×255, arg2=B×255` | same |
| `0x1E` | RGB effect ON | — | — |
| `0x1F` | RGB effect OFF | — | — |
| `0x23` | Night mode | (cold=0.1, warm=0.1) | same |

**`0x21` param/flag values:**

| flag | arg (cold/warm) | Meaning |
|------|-----------------|---------|
| 0x00 | 0–255 each | Set brightness + CT directly |
| 0x18 | 0, 0 | CT step warmer (K-) |
| 0x24 | 0, 0 | CT step colder (K+) |
| 0x14 | 0, 0 | Brightness step up |
| 0x28 | 0, 0 | Brightness step down |
| 0x01 | 127, 127 | Half-brightness preset |
| 0x02 | 255, 255 | Full-brightness preset |
| 0x40 | 0–255 each | Cycle color (remote only) |

#### Fan commands

| cmd | Action | Args |
|-----|--------|------|
| `0x31` | Fan 3-speed (V1) | `arg0=0 (off) or 1-3 (speed), arg1=0` |
| `0x32` | Fan 6-speed (V1) | `arg0=1-6 (speed), arg1=6` |
| `0x31` | Fan speed (V2, 6-speed) | `arg0=0x20, arg1=0 (off) or 1-6 (speed)` |
| `0x31` | Fan speed (V2, 3-speed) | `arg0=0x00, arg1=0 (off) or 1-3 (speed)` |
| `0x15` | Fan direction | `arg0=0 (forward), 1 (reverse)` |
| `0x16` | Fan oscillation | `arg0=0 (off), 1 (on)` |
| `0x33` | Fan preset | `arg0=0 (off), 1 (sleep), 2 (breeze)` |
| `0x47` | Direction toggle + ON | (remote only) |

#### Step / timer / system commands

| cmd | Action | Args |
|-----|--------|------|
| `0x04` | Brightness step up | `arg3 = step × 25` |
| `0x05` | Brightness step down | `arg3 = step × 25` |
| `0x06` | CT step colder (K+) | `arg3 = step × 25` |
| `0x07` | CT step warmer (K-) | `arg3 = step × 25` |
| `0x28` | Pair | special (id bytes in arg0/arg1) |
| `0x45` | Unpair | — |
| `0x6F` | All OFF | (remote only) |
| `0x41` | Timer (V2) | `arg0 = minutes` |
| `0x51` | Timer (V1) | `arg0 = minutes` |
| `0x48` | Beep toggle | — |

---

## 2. Zhi Jia / Zhi Guang

**App:** Zhi Jia Standard (Android)  
**Source:** `zhijia.py`

Shared utility: `pivot(buffer, index_set)` — XOR bytes at positions in `index_set` together, store result back; used to scramble/unscramble packet structure.

---

### 2.1 ZhijiaEncoderV0

```
_len = 13
_pivot_index = {0, 1, 6, 7}
_pivot_xor = False
CRC16: ISO14443AB (poly=0x8408, seed=0)
```

**Encrypt:**
1. `whiten(seed=0x37)` then `whiten(seed=0x7F)`
2. Append `CRC16` LE16

**Packet layout (13 bytes):**

| Byte | Field |
|------|-------|
| [0] | `uuid[0]` |
| [1] | `arg0` |
| [2] | `index` |
| [3] | `arg1` |
| [4] | `cmd` |
| [5] | `uuid[1]` |
| [6] | `uuid[0] ^ tx_count` |
| [7] | `arg0 ^ arg2` |
| [8:11] | pivot bytes |
| [11:13] | CRC16 LE |

**Variants:**

| ID | MAC | Header | Prefix | BLE type | ad_flag |
|----|-----|--------|--------|----------|---------|
| `zhijia_v0` | [0x19,0x01,0x10] | `[0xF9,0x08,0x49]` | `[0x08,0x80,0x98]` | 0xFF | 0x1A |
| `zhiguang_v0` | [0x20,0x03,0x05] | same | same | 0xFF | 0x1A |

---

### 2.2 ZhijiaEncoderV1

```
_len = 23
_tx_step = 2
_pivot_index = {2, 4, 9, 12, 13, 15}
_pivot_xor = True
_mac: 3-byte device identifier
```

**Encrypt:**
1. `whiten(seed=0x37)`
2. Append `CRC16` LE16
3. Apply `pivot` to scramble

**Packet layout (23 bytes after de-pivot):**

| Byte | Field |
|------|-------|
| [0] | `arg0` |
| [1] | key XOR combination |
| [2] | `uuid[0]` |
| [3] | `arg1` |
| [4] | `tx_count` |
| [5] | `arg2` |
| [6] | `index` |
| [7] | `mac[0]` |
| [8] | `0x00` (validation) |
| [9] | `cmd` |
| [10] | `mac[1]` |
| [11] | `0x00` (validation) |
| [12] | `uuid[1] ^ uuid[0]` |
| [13] | `mac[2] ^ tx_count` |
| [14] | dup of [7] |
| [15] | `uuid[2] ^ cmd` |
| [16] | `0x00` |
| [17:21] | padding |
| [21:23] | CRC16 LE |

**Variants:**

| ID | MAC | Header | Prefix | BLE type | ad_flag |
|----|-----|--------|--------|----------|---------|
| `zhijia_v1` | `[0x19,0x01,0x10]` | `[0xF9,0x08,0x49]` | `[0x55,0x08,0x80,0x98]` | 0xFF | 0x1A |
| `zhiguang_v1` | `[0x20,0x03,0x05]` | `[0xF9,0x08,0x49]` | `[0xA0,0xC0,0x04,0x04]` | 0xFF | 0x1A |

---

### 2.3 ZhijiaEncoderV2

Subclass of V1 with different whitening and pivot.

```
_len = 24
_pivot_index = {3, 7, 11, 12, 13, 15}
```

**Encrypt:**
1. `whiten(seed=0x6F)` then `whiten(seed=0xD3)` (except last 2 bytes)
2. Append 7 zero bytes

**Variants:**

| ID | MAC | Header | BLE type | ad_flag | Notes |
|----|-----|--------|----------|---------|-------|
| `zhijia_v2` | `[0x19,0x01,0x10]` | `[0x22,0x9D]` | 0xFF | 0x1A | |
| `zhijia_v2_fl` | `[0x19,0x01,0x10]` | `[0x22,0x9D]` | 0xFF | 0x1A | different translators (no reverse on some cmds) |
| `zhiguang_v2` | `[0x20,0x03,0x05]` | `[0x22,0x9D]` | 0xFF | 0x1A | |

---

### 2.4 ZhijiaEncoderRemote

Subclass of V1. No crypto (identity encrypt/decrypt). Decodes by XOR-ing entire buffer by `buf[5]` then calling V1's `convert_to_enc`.

| ID | match_id | MAC | Header | BLE type | ad_flag |
|----|----------|-----|--------|----------|---------|
| `zhijia_vr1` | `zhijia_v1` | `[0x20,0x03,0x05]` | `[0xF0,0xFF]` | 0xFF | 0x1A |

---

### 2.5 Zhi Jia Command Table

| cmd | Action | Args |
|-----|--------|------|
| `0xB4` / `0xA2` | Pair | — |
| `0xB0` / `0xA3` | Unpair | — |
| `0xB2` | Light OFF | — |
| `0xB3` / `0xA5` | Light ON | — |
| `0xA6` | Second light | `arg0=1 (off), 2 (on)` |
| `0xB5` | Brightness | `split_copy BR → [arg2, arg1] × 1000` |
| `0xB7` | CT | `split_copy CT → [arg2, arg1] × 1000` |
| `0xD0` | Fan speed 1 | — |
| `0xD1` | Fan speed 2 | — |
| `0xD2` | Fan speed 3 | — |
| `0xD8` | Fan OFF | — |
| `0xD9` | Fan direction forward | — |
| `0xDA` | Fan direction reverse | — |
| `0xD4–0xD7` | Timer | 60/120/240/480 min |
| `0xA1`,`0xA7` | Night mode / shortcuts | (reverse only) |

---

## 3. Zhi Mei

**App:** Zhi Mei Standard (Android)  
**Source:** `zhimei.py`

---

### 3.1 ZhimeiEncoderV0

```
_len = 9
Crypto: none (identity)
Checksum: sum(buffer + header) & 0xFF
```

**Packet layout (9 bytes):**

| Byte | Field |
|------|-------|
| [0] | `index` |
| [1] | `tx_count` |
| [2:4] | `id` LE16 |
| [4] | `cmd` |
| [5:8] | `arg0, arg1, arg2` |
| [8] | checksum |

| ID | Header | BLE type | ad_flag |
|----|--------|----------|---------|
| `zhimei_fan_v0` | `[0x55]` | 0x03 | 0x19 |
| `zhimei_fan_vr0` | `[0x55]` | 0x00 | 0x00 |

---

### 3.2 ZhimeiEncoderV1

```
_len = 16
_seed_max = 0xF5
CRC16: crc_hqx(buffer, 0)
MATRIX: 16-element substitution table
Footer: [0x10, 0x11, 0x12, 0x13, 0x14, 0x15]
```

**Encrypt:**
1. Apply MATRIX transformation (key=6)
2. Append CRC16

**Packet layout (16 bytes):**

| Byte | Field |
|------|-------|
| [0] | `0xFF` (validation) |
| [1] | `seed` |
| [2] | `tx_count` |
| [3:7] | `id` LE32 |
| [7] | `cmd` |
| [8] | `index` |
| [9] | `0xFF` (validation) |
| [10] | `tx_count` (duplicate) |
| [11:14] | `arg0, arg1, arg2` |
| [14:16] | CRC16 |

| ID | Header | Header start pos | BLE type | ad_flag |
|----|--------|-----------------|----------|---------|
| `zhimei_fan_v1` | `[0x48,0x46,0x4B,0x4A]` | 0 | 0x03 | 0x1A |
| `zhimei_v1` | `[0x48,0x46,0x4B,0x4A]` | 0 | 0x03 | 0x1A |
| `zhimei_fan_vr1` | `[0x48,0x46,0x4B,0x4A]` | 3 | 0xFF | 0x1A |
| `zhimei_fan_v1b` | `[0x00,0x00,0x00,0x48,0x46,0x4B,0x4A]` | 0 | 0xFF | 0x1A |
| `zhimei_v1b` | `[0x58,0x55,0x18,0x48,0x46,0x4B,0x4A]` | 0 | 0xFF | 0x1A |

---

### 3.3 ZhimeiEncoderV2

```
_len = 13
CRC16: reverse_all → crc_hqx(reversed, 0xFFFF) → reverse result
Whiten: seed=0x48
```

**Encrypt:**
1. Compute CRC, apply pivot XOR across specific bytes
2. `whiten(seed=0x48)`

**Packet layout (8 bytes decoded after de-pivot):**

| Byte | Field |
|------|-------|
| [0] | `id[1]` |
| [1] | `arg0` |
| [2] | `index` |
| [3] | `arg1` |
| [4] | `cmd` |
| [5] | `id[0]` |
| [6] | `tx_count ^ id[1]` |
| [7] | `arg0 ^ arg2` |
| [8:10] | CRC16 |

| ID | Header | Prefix | BLE type | ad_flag |
|----|--------|--------|----------|---------|
| `zhimei_v2` | `[0xF9,0x08,0x49]` | `[0x33,0xAA,0x55]` | 0x03 | 0x1A |

---

### 3.4 Zhi Mei Command Table

| cmd | Action | Args |
|-----|--------|------|
| `0xB4` | Pair | — |
| `0xB0` | Unpair | — |
| `0xB2` | Light OFF | — |
| `0xB3` | Light ON | — |
| `0xA6` | Second light | `arg0=1 (off), 2 (on)` |
| `0xB5` | Brightness | `arg0=mode(0); split_copy BR → [arg2, arg1]` |
| `0xB7` | CT | `arg0=mode(0); split_copy CT_REV → [arg2, arg1]` |
| `0xCA` | RGB | `arg0/arg1/arg2 = R/G/B × 255` |
| `0xA1` | Night mode | (reverse only) |
| `0xD1`,`0xD3`,`0xD4`,`0xDB` | Fan control | varies |
| `0xD9` | Fan direction forward | — |
| `0xDA` | Fan direction reverse | — |
| `0xDE` | Fan oscillation | `arg0=1 (on), 2 (off)` |

---

## 4. Agarce

**App:** Smart Light  
**Source:** `agarce.py`

```
_len = 18
_seed_max = 0xFFF5
Duration: 400ms, interval: 10ms, repeat: 60×
MATRIX = [0xAA, 0xBB, 0xCC, 0xDD, 0x5A, 0xA5, 0xA5, 0x5A]
```

**Encrypt:**
1. Extract `seed` from `decoded[1:3]`
2. Compute inner checksum of `decoded[0:15]`
3. XOR `buf[3:]` with MATRIX using `pivot0=seed_lo, pivot1=seed_hi`
4. Append checksum XOR'd with header checksum

**Decrypt:**
1. Validate outer checksum
2. Unwhiten using MATRIX + seed
3. Validate inner checksum
4. Decode pair fields from prefix nibbles if `arg0 & 0xF0` (pair marker)

**Packet layout (18 bytes):**

| Byte | Field |
|------|-------|
| [0] | prefix (`0x83` or `0x84`) |
| [1:3] | `seed` LE16 |
| [2] | `tx_count` |
| [3] | `app_restart_count` |
| [4] | `0x00` (rem_seq high) |
| [5] | `0x10` (rem_seq low) |
| [6:10] | `id` LE32 |
| [10] | `cmd` (& 0xF0 for pair flag) |
| [11:14] | `arg0, arg1, arg2` |
| [14] | `index` |
| [15] | inner checksum |
| [16] | outer checksum |

**Commands:**

| cmd | Action | Args |
|-----|--------|------|
| `0x00` | Pair / Unpair | `arg0=0 (unpair), 1 (pair)` |
| `0x10` | Light on/off + CT | `arg0=0(off)/1(on), arg1=CT×100, arg2=BR×100` |
| `0x20` | CT Light direct | `arg0=CT×100, arg1=BR×100` |
| `0x70` | Device ON/OFF | `arg0=0-1(off), 2+(on)` (reverse only) |
| `0x80` | Fan | `arg0` bit-packed: bit7=on, bits3-0=speed, bit4=dir_rev, bit5=breeze; `arg1=oscillation, arg2=change_flags` |

**Variants:**

| ID | Prefix byte | Header | BLE type | ad_flag |
|----|------------|--------|----------|---------|
| `agarce_v3` | `0x83` | `[0xF9,0x09]` | 0xFF | 0x19 |
| `agarce_v4` | `0x84` | `[0xF9,0x09]` | 0xFF | 0x19 |

---

## 5. Mantra

**App:** Mantra Lighting Application  
**Source:** `mantra.py`

```
_len = 18
_tx_max = 0x0FFF  (12-bit counter)
Duration: 400ms, interval: 100ms, repeat: 6×
_family = [0x12, 0x34, 0x56, 0x78]
```

**Custom `whiten16`:** 16-bit LFSR (param=4777, xorer=73), applied to `buf[5:]` using `seed = buf[2:4]`.

**Packet layout (18 bytes):**

| Bytes | Field |
|-------|-------|
| [0:2] | `tx_count` (lower 12 bits) + `index` (bits 12-15) |
| [2] | `0x06` (validation) |
| [3] | `cmd` |
| [4:8] | family `[0x12,0x34,0x56,0x78]` |
| [8:10] | `id` LE16 |
| [10] | `param` |
| [11:16] | `arg0, arg1, arg2, arg3, arg4` |

**Commands:**

| cmd | param | Action | Args |
|-----|-------|--------|------|
| `0x01` | `0x02` | Device OFF | — |
| `0x01` | `0x05`/`0x06` | Main light ON/OFF | — |
| `0x01` | `0x07`/`0x08` | Fan ON/OFF | — |
| `0x01` | `0x09–0x0C` | Timer | — |
| `0x01` | `0x0D`/`0x0E` | Preset (breeze/sleep) | — |
| `0x02` | `warm×255` | CT light | `arg0=cold×255, arg1=BR×7, arg2=CT_REV×6, arg3=BR×255, arg4=CT_REV×255` |
| `0x03` | `0x01` | Fan speed | `arg0 = 1–31 mapped to speed` |
| `0x10` | varies | Remote button | reverse-only |

**Variants:**

| ID | Prefix | Header | Footer | BLE type | ad_flag |
|----|--------|--------|--------|----------|---------|
| `mantra_v0` | `[0x72,0x0E]` | `[0x4E,0x6F]` | — | 0xFF | 0x1A |
| `mantra_v0/ios` | `[0x72,0x0E]` | `[0x4E,0x6F]` | `[0x04,0x03,0x02,0x01]` | 0x05 | 0x1A |
| `mantra_v1` | `[0x72,0x0F]` | `[0x4E,0x6F]` | — | 0xFF | 0x1A |
| `mantra_v1/ios` | `[0x72,0x0F]` | `[0x4E,0x6F]` | `[0x04,0x03,0x02,0x01]` | 0x05 | 0x1A |

---

## 6. RuiXin

**App:** RuiXin  
**Source:** `ruixin.py`

```
_len = 16 (app) / 19 (remote)
_seed_max = 0xF5
```

**Encrypt:**
1. Pad to `_len` with zeros (app) or specific bytes (remote)
2. XOR `buf[2:16]` with `(buf[0] + i) & 0xFF` for each offset `i`
3. Append checksum

**Packet layout (10 bytes decoded):**

| Byte | Field |
|------|-------|
| [0] | `seed` |
| [1] | `tx_count` |
| [2:6] | `id` LE32 |
| [6] | `cmd` |
| [7:10] | `arg0, arg1, arg2` |

**Commands:**

| cmd | Action | Args |
|-----|--------|------|
| `0xAA` | Pair | — |
| `0x01` | Light ON | — |
| `0x02` | Light OFF | — |
| `0x21` | Light toggle | (reverse only) |
| `0x0C` | Brightness | `arg0 = BR × 250` |
| `0x0D` | CT | `arg0 = CT × 250` |
| `0x03–0x06` | Fan control | varies |
| `0x10` | Fan speed | `arg0 = speed` |
| `0x11` | Device OFF | (reverse only) |

**Variants:**

| ID | Class | Header | BLE type | ad_flag |
|----|-------|--------|----------|---------|
| `ruixin_v0` | `RuiXinEncoder` | `[0xFF,0xFF,0x01,0x02,0x03,0x04,0x69,0x72,0x36,0x0E]` | 0xFF | 0x00 |
| `ruixin_v0/r1` | `RuiXinRemoteEncoder` | `[0x00,0x00,0x00,0x52,0x58,0x4B,0x69,0x72,0x36,0x0E]` | 0xFF | 0x00 |

---

## 7. Smart Elfin

**App:** Smart Elfin  
**Source:** `smartelfin.py`

```
_len = 12
_tx_max = 0xFE
_tx_step = 2
_FIXED = [0x64, 0xE5, 0xE3, 0xBA]
second_type = 0x16
second_raw = [0x00] * 8
```

**Crypto:** Insert/remove 4 fixed bytes at position 4.  
**Decrypt:** Remove `buf[4:8]` (must equal `_FIXED`).  
**Encrypt:** Insert `_FIXED` at position 4.

**Packet layout (12 bytes total, 8 bytes payload):**

| Byte | Field |
|------|-------|
| [0:3] | `id` LE24 |
| [3] | `tx_count` |
| [4:8] | `_FIXED` (stripped in decode) |
| [4] | `param` (decoded position) |
| [5] | `cmd` (decoded position) |
| [6:8] | `arg0, arg1` (decoded positions) |

**Commands:**

| cmd | param | Action | arg1 |
|-----|-------|--------|------|
| `0xFB` | — | Pair | `0x03` |
| `0xFD` | — | Unpair | `0x00` |
| `0x03` | `0x0F` | Light 0 | `0=off, 1=on, 2=toggle` |
| `0x06` | `0x0F` | Light 1 | same |
| `0x0C` | `0x0F` | Brightness step | `1=up, 2=down` |
| `0x0D` | `0x0F` | CT step | `1=up, 2=down` |
| `0x0E` | `0x0F` | Brightness set | `arg1 = BR × 100` |
| `0x0F` / `0x13` | `0x0F` | CT set | `arg1 = CT × 100 (0=cold, 50=mid, 100=warm)` |
| `0x04` | `0x0F` | Fan direction | `0x01=forward, 0x02=reverse` |
| `0x05` | `0x0F` | Fan oscillation | `0x01=off, 0x02=on` |
| `0x01` | `0x0F` | Fan preset | `0=off, 1=breeze, 2=sleep` |
| `0x02` | — | Fan speed | `arg1 = speed × 10` |
| `0x09` | — | Timer | `arg1 = 0x00 (2h), 0x01 (4h)` |

| ID | Header | BLE type | ad_flag |
|----|--------|----------|---------|
| `smartelfin_v0` | `[0x57,0x46,0x54,0x58]` | 0x07 | 0x02 |

---

## 8. LE Light

**App:** LE Light  
**Source:** `le.py`

```
_len = 21
XBOXES = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, ...]  (16 elements)
```

**Encrypt:**
1. Compute checksum: `((sum(buf) + 1) & 0xFF) ^ 0xFF`
2. Append checksum
3. XOR `buf[6:]` with `XBOXES[salt & 15]` where `salt = buf[2]`
4. Pad remainder to `_len` with zeros

**Packet layout (decoded, 12 bytes):**

| Byte | Field |
|------|-------|
| [0] | `data_len` |
| [1] | `0x01` (marker) |
| [2:6] | `id` LE32 |
| [4] | `0xFE` (marker) |
| [5] | `index` |
| [6] | `tx_count` |
| [7] | `cmd` |
| [8] | `param` (arg count) |
| [9:12] | `arg0, arg1, arg2` |
| [12] | checksum |

**Commands:**

| cmd | param | Action | Args |
|-----|-------|--------|------|
| `0x00` | 1 | Pair | `arg0=1` (reverse only) |
| `0x01` | 1 | Light OFF | `arg0=1` |
| `0x08` | 2 | Brightness | `split_copy BR → [arg1, arg0] × 1000 mod 256` |
| `0x0D` | 2 | CT | `arg0=128 if cold≤0.5, arg1=CT×256` |
| `0x12` | 2 | Night light | `arg0=0, arg1=5` (reverse only) |
| `0x16` | 3 | RGB | `arg0/arg1/arg2 = R/G/B × 255` |
| `0x21` | 1 | Fan | `arg0=0(off), 1-3(speed), 128/129(direction)` |
| `0x22` | 3 | Timer | `arg0=0, arg1/arg2=time portions` |

| ID | Header | BLE type | ad_flag |
|----|--------|----------|---------|
| `lelight` | `[0xFF,0xFF,0xFF,0xFF]` | 0xFF | 0x1A |

---

## 9. RW.Light

**App:** RW.Light  
**Source:** `rw.py`

```
_len = 18
_seed_max = 0xF5
CRC16: crc_hqx(buffer, 0x696B)
```

**Encrypt:**
1. Extract `seed` (last byte of decoded)
2. Compute `b12 = buf[1] ^ buf[2]`
3. Build 16-byte intermediate from XOR combinations of decoded fields
4. Insert fixed validation bytes: `0x4C` at [8], `0xFF` at [9], `0x00` at [10], `0x01` at [12], `0x02` at [14]
5. Append CRC16
6. `whiten(seed=0x69)` → `reverse_all()`

**Decrypt:**
1. `reverse_all()` → `whiten(seed=0x69)`
2. Validate fixed bytes at positions 8, 9, 10, 12, 14
3. Extract pivot from bytes [11, 13, 15]
4. XOR-decode using pivot

**Packet layout (11 bytes decoded):**

| Byte | Field |
|------|-------|
| [0] | `cmd` |
| [1] | `tx_count` |
| [2:6] | `id` LE32 |
| [6] | `index` |
| [7:10] | `arg0, arg1, arg2` |
| [10] | `seed` |

**Commands:**

| cmd | Action | Args |
|-----|--------|------|
| `0x01`/`0x02` | Light 0 OFF/ON | — |
| `0x10`/`0x11` | Light 2 OFF/ON | — |
| `0x0B` | Brightness | `arg0 = BR × 100` |
| `0x0C` | CT | `arg0 = CT × 100` |
| `0x07–0x0A` | Light effects | Theater / Party / Night / Reading |
| `0x31`/`0x32` | RGB light OFF/ON | — |
| `0x48` | RGB color | `arg0=(G<<4)∣R, arg1=B, arg2=BR×100` |
| `0x3B–0x3F`,`0x43` | RGB effects | varies |
| `0x61`/`0x62` | Fan control | — |
| `0x63` | Timer | `arg1=time` |
| `0x76`/`0x78` | Pair / Unpair | — |

**Variants:**

| ID | Header | BLE type | ad_flag |
|----|--------|----------|---------|
| `rwlight_mix` | `[0xDD,0xB2,0xDA,0x6C,0x9F,0x01,0x7A,0x34]` | 0xFF | 0x1A |
| `rwlight_mix/ios` | same | 0x03 | 0x1A |

---

## 10. Physical Remotes (no-name)

**Source:** `remotes.py`

```
_len = 8
Crypto: none
Checksum: sum(buffer) & 0xFF
```

**Packet layout (8 bytes):**

| Byte | Field |
|------|-------|
| [0] | `arg0` (step or param) |
| [1:5] | `id` LE32 |
| [5] | `cmd` (lower 6 bits) + `arg1` (upper 2 bits) |
| [6] | `tx_count` |
| [7] | checksum |

**Commands:**

| cmd | Action | arg0 |
|-----|--------|------|
| `0x02` | CT warmer | `step × 10` |
| `0x03` | CT colder | `step × 10` |
| `0x06` | Light OFF | — |
| `0x08` | Light ON | — |
| `0x0A` | Brightness up | `step × 10` |
| `0x0B` | Brightness down | `step × 10` |
| `0x07` | CT/BR cycle | — |
| `0x10` | Night mode | (reverse only) |
| `0x13` | Light toggle | (reverse only) |

| ID | Header | BLE type | ad_flag |
|----|--------|----------|---------|
| `remote_v4` | `[0xF0,0xFF]` | 0xFF | 0x1A |

---

## Attribute Scaling Reference

| Attribute | HA range | Encoding | Factor |
|-----------|----------|----------|--------|
| Brightness (BR) | 0.0–1.0 | `× 255` | 255 |
| Brightness (BR) | 0.0–1.0 | `× 100` | 100 |
| Color temp (cold) | 0.0–1.0 | `× 255` | 255 |
| Color temp (warm) | 0.0–1.0 | `× 255` | 255 |
| CT split | 0.0–1.0 | `split_copy × 1000 mod 256` into 2 bytes | 1000 |
| Fan speed | 1–N | raw integer | — |
| RGB | 0.0–1.0 per channel | `× 255` | 255 |
| RGB (rw) | 0.0–1.0 per channel | 4-bit nibble `× 15` | 15 |
| Timer | seconds | `/ 60` = minutes | 1/60 |
| CT step | 0.0–1.0 | `× 25` | 25 |
