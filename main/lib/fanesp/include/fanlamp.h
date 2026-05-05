#pragma once

#include "ble_adv_codec.h"

#include <cstdint>
#include <vector>

namespace fanesp::codecs {

// ============================================================================
// FanLampEncoder
// ============================================================================

/**
 * @brief Shared base for all FanLamp Pro / LampSmart Pro codecs.
 *
 * Provides the CRC16-CCITT helper used by all FanLamp V1 and V2 variants.
 * Payload length for all variants is 24 bytes (set before any header adjustment).
 */
class FanLampEncoder : public Codec {
protected:
    /**
     * @brief CRC16-CCITT (poly=0x1021) matching Python binascii.crc_hqx.
     *
     * @param buf   Data to checksum.
     * @param seed  Initial CRC value.
     * @return      16-bit CRC.
     */
    static uint16_t _crc16(const std::vector<uint8_t>& buf, uint16_t seed);

    /// @brief Raw payload size shared by all FanLamp variants before header adjustments.
    static constexpr int BASE_LEN = 24;

    FanLampEncoder() { _len = BASE_LEN; }
};

// ============================================================================
// FanLampEncoderV1Base
// ============================================================================

/**
 * @brief FanLamp V1 base codec: whiten(0x0C) → reverse_all, with CRC2 outer checksum.
 *
 * Decrypt pipeline:
 *   buffer (16 B) → whiten(seed=0x0C) → reverse_all → decoded (16 B)
 *   → verify decoded[-2:] == _crc2(decoded[:-2])
 *   → return decoded[:-2]  (14 B)
 *
 * Encrypt pipeline:
 *   buf (14 B) → append CRC2(2 B) → reverse_all → whiten(seed=0x0C)
 *   → return (16 B)
 *
 * The header() override appends an 8-byte whitened/reversed PREFIX to the
 * caller-supplied header bytes and subtracts len(PREFIX) from _len so the
 * total packet length remains 26 bytes.
 *
 * @note _forced_crc2 allows remote-control variants to supply a fixed CRC2
 *       value instead of the computed one (some remotes always send 0x9372).
 */
class FanLampEncoderV1Base : public FanLampEncoder {
public:
    /// @brief 8-byte fixed PREFIX embedded in every V1Base packet header.
    static constexpr uint8_t PREFIX[8] = {0xAA, 0x98, 0x43, 0xAF, 0x0B, 0x46, 0x46, 0x46};

    /**
     * @brief Override forced CRC2 (bypasses computation).
     *
     * Used by remote-control codecs that always transmit a fixed CRC2 word
     * (e.g. 0x9372 or 0x0000) regardless of payload content.
     *
     * @param crc2  The forced CRC2 value to use.
     */
    FanLampEncoderV1Base& forced_crc2(uint16_t crc2);

    /**
     * @brief Set the header, embedding the whitened/reversed PREFIX.
     *
     * Appends whiten(reverse_all(PREFIX), 0x6F) to the caller-supplied base
     * header bytes, then subtracts sizeof(PREFIX) from _len so the total
     * on-wire length stays constant.
     *
     * @param hdr       Base header bytes (typically 2–5 bytes).
     * @param start_pos Byte offset of the header within the payload (default 0).
     */
    Codec& header(std::vector<uint8_t> hdr, int start_pos = 0) override;

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t>               encrypt(const std::vector<uint8_t>& decoded) override;

protected:
    std::optional<uint16_t> _forced_crc2; ///< When set, overrides computed CRC2.

    /**
     * @brief Compute the outer CRC2 checksum.
     *
     * Returns _forced_crc2 if set; otherwise CRC16-CCITT(buf, seed=0xA5BE).
     * 0xA5BE == crc_hqx([0x98, 0x43, 0xAF, 0x0B, 0x46], 0xFFFF).
     */
    uint16_t _crc2(const std::vector<uint8_t>& buf) const;
};

// ============================================================================
// FanLampEncoderV1R0
// ============================================================================

/**
 * @brief FanLamp V1 R0 codec: V1Base crypto without inner CRC16 or seed logic.
 *
 * Simplified remote-control / older-firmware variant.  convert_to_enc() reads
 * a flat layout without the 14-byte inner CRC block that V1 requires.
 *
 * When _null_trailers is true (V1R1), bytes [8..13] of the decrypted payload
 * must be 0x00.
 *
 * Decoded payload layout (14 bytes):
 *   [0]      cmd
 *   [1:3]    group_index little-endian  → index=(bits 11:8), id=(bits 15:12 | 7:0)
 *   [3]      arg0
 *   [4]      arg1
 *   [5]      arg2
 *   [6]      arg3
 *   [7]      param
 *   [8:14]   trailers (null-checked when _null_trailers=true)
 */
class FanLampEncoderV1R0 : public FanLampEncoderV1Base {
public:
    FanLampEncoderV1R0();

    bool                 convert_to_enc(const std::vector<uint8_t>& decoded,
                                         BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x03; }

protected:
    bool _null_trailers = false; ///< When true, trailer bytes [8..13] must be 0x00.
};

// ============================================================================
// FanLampEncoderV1R1
// ============================================================================

/**
 * @brief FanLamp V1 R1 codec: identical to V1R0 with mandatory null trailers.
 *
 * Sets _null_trailers = true and forces forced_crc2 = 0x0000.
 */
class FanLampEncoderV1R1 : public FanLampEncoderV1R0 {
public:
    FanLampEncoderV1R1();
    uint8_t get_codec_id() const override { return 0x04; }
};

// ============================================================================
// FanLampEncoderV1
// ============================================================================

/**
 * @brief FanLamp V1 full codec: V1Base crypto with inner CRC16-CCITT and seed.
 *
 * Adds a 14-byte inner block validated by:
 *   - CRC16-CCITT(decoded[0..11], seed ^ 0xFFFF) == decoded[12:14]
 *   - _get_arg2(cmd, decoded[5]) == decoded[5]
 *   - seed8 (or seed8^1 when xor1) == decoded[9]
 *
 * Seed max is 0xFFF5 (seed always < 0xFFF6).
 *
 * _arg2 is injected as a fixed value into certain command bytes:
 *   - cmd == 0x28 (pair):     always inject _arg2
 *   - cmd == 0x22:            pass through enc_cmd.arg2 unchanged
 *   - other commands:         inject _arg2 only when !_arg2_only_on_pair and
 *                             cmd not in {0x12, 0x13, 0x1E, 0x1F}
 *
 * Decoded payload layout (14 bytes after CRC2 strip):
 *   [0]      cmd
 *   [1:3]    group_index → index / id extraction
 *   [3]      arg0 (or id & 0xFF on pair)
 *   [4]      arg1 (or (id >> 8) & 0xF0 on pair)
 *   [5]      arg2 (validated by _get_arg2)
 *   [6]      tx_count
 *   [7]      param
 *   [8]      seed8 ^ id_high_byte (or seed8^1 when xor1)
 *   [9]      seed8 (or seed8^1 when xor1)
 *   [10:12]  seed big-endian
 *   [12:14]  inner CRC16-CCITT
 */
class FanLampEncoderV1 : public FanLampEncoderV1Base {
public:
    /**
     * @param arg2              Fixed byte injected for pair / all commands (codec-specific).
     * @param arg2_only_on_pair When true, only inject arg2 for cmd == 0x28 (pair).
     * @param xor1              When true, encode seed8 XOR 1 in decoded[8:9] instead of
     *                          seed8 XOR id_high_byte / seed8.
     */
    FanLampEncoderV1(uint8_t arg2, bool arg2_only_on_pair = true, bool xor1 = false);

    bool                 convert_to_enc(const std::vector<uint8_t>& decoded,
                                         BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    std::vector<SupportedFeature> get_supported_features() const override;
    uint8_t get_codec_id() const override { return 0x01; }

protected:
    uint8_t _arg2;
    bool    _arg2_only_on_pair;
    bool    _xor1;

    /**
     * @brief Determine the arg2 byte to embed for a given command byte and enc_cmd.arg2.
     *
     * Logic (in priority order):
     *   cmd == 0x22  → return enc_cmd_arg2 unchanged
     *   cmd == 0x28  → return _arg2
     *   !_arg2_only_on_pair && cmd not in {0x12,0x13,0x1E,0x1F} → return _arg2
     *   otherwise    → return 0
     */
    uint8_t _get_arg2(uint8_t cmd, uint8_t enc_arg2) const;
};

// ============================================================================
// FanLampEncoderV1aa
// ============================================================================

/**
 * @brief FanLamp V1aa codec: V1 with a different whiten seed and 0xAA trailer.
 *
 * Replaces the CRC2 outer checksum of V1Base with a single 0xAA trailer byte:
 *
 * Decrypt pipeline:
 *   buffer (15 B) → whiten(seed=0x2B) → reverse_all → decoded (15 B)
 *   → verify decoded[14] == 0xAA
 *   → return decoded[0..13]  (14 B)
 *
 * Encrypt pipeline:
 *   buf (14 B) → append 0xAA → reverse_all → whiten(seed=0x2B)
 *   → return (15 B)
 *
 * Its PREFIX is [0x55] prepended to FanLampEncoderV1Base::PREFIX (9 bytes total),
 * so header() subtracts 9 from _len (giving _len = 15).
 */
class FanLampEncoderV1aa : public FanLampEncoderV1 {
public:
    using FanLampEncoderV1::FanLampEncoderV1;

    /// @brief Extended PREFIX: [0x55] + FanLampEncoderV1Base::PREFIX (9 bytes).
    static constexpr uint8_t PREFIX_AA[9] = {
        0x55, 0xAA, 0x98, 0x43, 0xAF, 0x0B, 0x46, 0x46, 0x46};

    Codec& header(std::vector<uint8_t> hdr, int start_pos = 0) override;

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t>               encrypt(const std::vector<uint8_t>& decoded) override;
    uint8_t get_codec_id() const override { return 0x05; }
};

// ============================================================================
// FanLampEncoderV2
// ============================================================================

/**
 * @brief FanLamp V2 codec: XBOXES-based whiten + optional AES-ECB sign + CRC16-CCITT.
 *
 * Decrypt pipeline (buffer = 24 B):
 *   seed       = LE16(buffer[20:22])
 *   crc_msg    = LE16(buffer[22:24])
 *   verify CRC16-CCITT(buffer[0:22], seed^0xFFFF) == crc_msg
 *   decoded_base = buffer[0:2] ++ _whiten(buffer[2:19], seed & 0xFF)   (19 B)
 *   sign = LE16(decoded_base[17:19])
 *   if with_sign: verify _sign(decoded_base[1:17], decoded_base[3], seed) == sign
 *   else:         verify sign == 0
 *   return decoded_base[0:17] ++ buffer[20:22]   (19 B, seed appended at tail)
 *
 * Encrypt pipeline (decoded = 3-prefix + 16-content B = 19 B, seed in decoded[-2:]):
 *   seed = LE16(decoded[17:19])
 *   obuf = decoded[0:17]
 *   append LE16(sign or 0)                       → 19 B
 *   append 0x00                                  → 20 B
 *   obuf = obuf[0:2] ++ _whiten(obuf[2:], seed&0xFF)
 *   append LE16(seed)                            → 22 B
 *   append LE16(CRC16-CCITT(obuf, seed^0xFFFF))  → 24 B
 *
 * Whitening uses XBOXES[((seed + i + 9) & 0x1F) + salt] ^ seed ^ val,
 * where salt = (prefix[1] & 0x3) << 5 distinguishes sub-slots.
 *
 * AES key = [seed_lo, seed_hi, tx_count, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
 *             0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
 * AES-ECB(key, plaintext[16]) → ciphertext; sign = LE16(ciphertext[0:2]) or 0xFFFF.
 *
 * Decoded payload layout (16 bytes, after 3-byte prefix strip):
 *   [0]      tx_count
 *   [1:3]    device_type LE16 (verified against _device_type)
 *   [3:7]    id LE32
 *   [7]      index
 *   [8]      cmd
 *   [9]      0 (reserved)
 *   [10]     param
 *   [11]     arg0
 *   [12]     arg1
 *   [13]     arg2
 *   [14:16]  seed LE16 (artificially appended during decrypt)
 */
class FanLampEncoderV2 : public FanLampEncoder {
public:
    /**
     * @param device_type  Expected 16-bit device type embedded in decoded[1:3].
     *                     FanLamp Pro = 0x0400, LampSmart Pro = 0x0100.
     * @param with_sign    When true, validate (on decode) and generate (on encode)
     *                     the AES-ECB signature in the packet.
     */
    FanLampEncoderV2(uint16_t device_type, bool with_sign);

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t>               encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                         BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    std::vector<SupportedFeature> get_supported_features() const override;
    BleAdvEncCmd make_light_cw_cmd(uint8_t cold, uint8_t warm) const override;
    uint8_t get_codec_id() const override { return 0x02; }

    /**
     * @brief 128-entry S-box for the custom whitening algorithm.
     *
     * Index = ((seed + byte_position + 9) & 0x1F) + salt,  where
     * salt = (prefix[1] & 0x3) << 5.  Maximum index = 0x7F.
     */
    static constexpr uint8_t XBOXES[128] = {
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    };

private:
    uint16_t _device_type;
    bool     _with_sign;

    /**
     * @brief Custom XBOXES-based whitening (symmetric: same function decrypts).
     *
     * For each byte i: out[i] = XBOXES[((seed+i+9)&0x1F) + salt] ^ seed ^ in[i]
     * where salt = (_prefix[1] & 0x3) << 5.
     */
    std::vector<uint8_t> _whiten(const std::vector<uint8_t>& buf, uint8_t seed) const;

    /**
     * @brief AES-128-ECB signature over a 16-byte block.
     *
     * Key construction: [seed_lo, seed_hi, tx_count, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
     *                    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
     * Returns LE16(AES(key, buf)[0:2]), substituting 0xFFFF if the result is 0.
     *
     * @param buf       Exactly 16-byte plaintext block.
     * @param tx_count  Contributes to key[2].
     * @param seed      Contributes to key[0..1].
     */
    uint16_t _sign(const std::vector<uint8_t>& buf, uint8_t tx_count, uint16_t seed) const;
};

/**
 * @brief Get all FanLamp codec instances configured and ready for use.
 *
 * Returns a vector of pointers to statically allocated codec instances.
 * Codecs are configured on first call and reused on subsequent calls.
 *
 * @return Vector of Codec pointers for all FanLamp variants.
 */
std::vector<fanesp::Codec*> get_fanlamp_codecs();

} // namespace fanesp::codecs
