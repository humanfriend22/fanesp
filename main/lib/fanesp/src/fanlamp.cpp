#include "fanlamp.h"

#include "ble_adv_utils.h"

#include <aes/esp_aes.h>

namespace fanesp::codecs {

// ─── FanLampEncoder ─────────────────────────────────────────────────────────

uint16_t FanLampEncoder::_crc16(const std::vector<uint8_t>& buf, uint16_t seed) {
    return crc16_ccitt(buf, seed);
}

// ─── FanLampEncoderV1Base ────────────────────────────────────────────────────

FanLampEncoderV1Base& FanLampEncoderV1Base::forced_crc2(uint16_t crc2) {
    _forced_crc2 = crc2;
    return *this;
}

Codec& FanLampEncoderV1Base::header(std::vector<uint8_t> hdr, int start_pos) {
    // Append whitened/reversed PREFIX to the caller's base header bytes.
    std::vector<uint8_t> pfx(PREFIX, PREFIX + sizeof(PREFIX));
    auto whitened = whiten(reverse_all(pfx), 0x6F);
    hdr.insert(hdr.end(), whitened.begin(), whitened.end());
    _header           = std::move(hdr);
    _header_start_pos = start_pos;
    // Compensate _len: the PREFIX bytes are folded into the header, not the payload.
    _len -= static_cast<int>(sizeof(PREFIX));
    return *this;
}

uint16_t FanLampEncoderV1Base::_crc2(const std::vector<uint8_t>& buf) const {
    if (_forced_crc2.has_value()) return _forced_crc2.value();
    // Seed 0xA5BE == crc_hqx([0x98,0x43,0xAF,0x0B,0x46], 0xFFFF)
    return _crc16(buf, 0xA5BE);
}

std::optional<std::vector<uint8_t>> FanLampEncoderV1Base::decrypt(
        const std::vector<uint8_t>& buffer) {
    auto decoded = reverse_all(whiten(buffer, 0x0C));
    if (decoded.size() < 2) return std::nullopt;

    // Last 2 bytes are CRC2; verify against the preceding data.
    uint16_t stored = static_cast<uint16_t>(decoded[decoded.size() - 2])
                    | (static_cast<uint16_t>(decoded[decoded.size() - 1]) << 8);
    std::vector<uint8_t> data(decoded.begin(), decoded.end() - 2);
    if (_crc2(data) != stored) return std::nullopt;

    return data;
}

std::vector<uint8_t> FanLampEncoderV1Base::encrypt(const std::vector<uint8_t>& decoded) {
    uint16_t crc     = _crc2(decoded);
    std::vector<uint8_t> with_crc(decoded);
    with_crc.push_back(static_cast<uint8_t>(crc & 0xFF));
    with_crc.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));
    return whiten(reverse_all(with_crc), 0x0C);
}

// ─── FanLampEncoderV1R0 ──────────────────────────────────────────────────────

FanLampEncoderV1R0::FanLampEncoderV1R0() {
    // Remote / simplified variant: reduce ign_duration to match Python ign_duration=300.
}

bool FanLampEncoderV1R0::convert_to_enc(const std::vector<uint8_t>& decoded,
                                          BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (_null_trailers) {
        // Bytes [8..13] must all be zero.
        if (decoded.size() < 14) return false;
        for (int i = 8; i < 14; i++) {
            if (decoded[i] != 0x00) return false;
        }
    }

    if (decoded.size() < 8) return false;

    uint16_t group_index = static_cast<uint16_t>(decoded[1])
                         | (static_cast<uint16_t>(decoded[2]) << 8);
    conf.index = static_cast<uint8_t>((group_index & 0x0F00u) >> 8);
    conf.id    = group_index & 0xF0FFu;

    enc_cmd      = BleAdvEncCmd{};
    enc_cmd.cmd  = decoded[0];
    enc_cmd.arg0 = decoded[3];
    enc_cmd.arg1 = decoded[4];
    enc_cmd.arg2 = decoded[5];
    enc_cmd.arg3 = decoded[6];
    enc_cmd.param = decoded[7];

    return true;
}

std::vector<uint8_t> FanLampEncoderV1R0::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                            const BleAdvConfig& conf) {
    uint16_t uid = static_cast<uint16_t>(conf.id & 0xF0FFu)
                 | static_cast<uint16_t>((conf.index & 0x0Fu) << 8);

    std::vector<uint8_t> trailers;
    if (_null_trailers) {
        trailers = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    } else if (enc_cmd.arg3 == 0) {
        uint8_t t0 = (enc_cmd.arg2 != 0) ? 0x05 : 0x02;
        uint8_t t4 = (enc_cmd.arg2 != 0) ? 0x02 : 0x01;
        trailers   = {t0, 0x00, 0x00, 0x00, t4, 0x00};
    } else {
        uint8_t id_hi = static_cast<uint8_t>((conf.id >> 8) & 0xFF);
        uint8_t id_lo = static_cast<uint8_t>(conf.id & 0xFF);
        uint8_t t5    = (enc_cmd.arg3 == 0x01) ? 0x01 : 0x00;
        trailers      = {id_lo, id_hi, 0x00, 0x00, enc_cmd.arg3, t5};
    }

    return {enc_cmd.cmd,
            static_cast<uint8_t>(uid & 0xFF),
            static_cast<uint8_t>((uid >> 8) & 0xFF),
            enc_cmd.arg0,
            enc_cmd.arg1,
            enc_cmd.arg2,
            enc_cmd.arg3,
            enc_cmd.param,
            trailers[0], trailers[1], trailers[2],
            trailers[3], trailers[4], trailers[5]};
}

// ─── FanLampEncoderV1R1 ──────────────────────────────────────────────────────

FanLampEncoderV1R1::FanLampEncoderV1R1() {
    _null_trailers = true;
    _forced_crc2 = 0x0000;
}

// ─── FanLampEncoderV1 ────────────────────────────────────────────────────────

FanLampEncoderV1::FanLampEncoderV1(uint8_t arg2, bool arg2_only_on_pair, bool xor1)
    : _arg2(arg2), _arg2_only_on_pair(arg2_only_on_pair), _xor1(xor1) {
    _seed_max = 0xFFF5;
}

uint8_t FanLampEncoderV1::_get_arg2(uint8_t cmd, uint8_t enc_arg2) const {
    if (cmd == 0x22) return enc_arg2;
    if (cmd == 0x28) return _arg2;
    if (!_arg2_only_on_pair) {
        // Inject _arg2 for all commands except these four.
        if (cmd != 0x12 && cmd != 0x13 && cmd != 0x1E && cmd != 0x1F) {
            return _arg2;
        }
    }
    return 0;
}

bool FanLampEncoderV1::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (decoded.size() < 14) return false;

    uint16_t seed  = static_cast<uint16_t>(decoded[10]) | (static_cast<uint16_t>(decoded[11]) << 8);
    uint8_t  seed8 = static_cast<uint8_t>(seed & 0xFF);

    // Inner CRC16-CCITT check over decoded[0..11] using seed as initial value.
    uint16_t crc_expected = static_cast<uint16_t>(decoded[12])
                          | (static_cast<uint16_t>(decoded[13]) << 8);
    std::vector<uint8_t> crc_input(decoded.begin(), decoded.begin() + 12);
    if (_crc16(crc_input, seed ^ 0xFFFFu) != crc_expected) return false;

    // arg2 consistency check.
    if (_get_arg2(decoded[0], decoded[5]) != decoded[5]) return false;

    // r2 field: seed8 or seed8^1.
    uint8_t expected_r2 = _xor1 ? (seed8 ^ 1u) : seed8;
    if (decoded[9] != expected_r2) return false;

    uint16_t group_index = static_cast<uint16_t>(decoded[1])
                         | (static_cast<uint16_t>(decoded[2]) << 8);
    conf.index    = static_cast<uint8_t>((group_index & 0x0F00u) >> 8);
    conf.tx_count = decoded[6];
    conf.seed     = seed;

    // High byte of id is derived from seed8 XOR decoded[8].
    uint32_t id_high = static_cast<uint32_t>(seed8 ^ decoded[8]) << 16;
    conf.id = (group_index & 0xF0FFu) | id_high;

    enc_cmd       = BleAdvEncCmd{};
    enc_cmd.cmd   = decoded[0];

    if (enc_cmd.cmd != 0x28) {
        enc_cmd.param = decoded[7];
        enc_cmd.arg0  = decoded[3];
        enc_cmd.arg1  = decoded[4];
        if (enc_cmd.cmd == 0x22) {
            enc_cmd.arg2 = decoded[5];
        }
    } else {
        // Pair command: verify arg0/arg1 encode id fields.
        enc_cmd.param = (_arg2 == 0x00) ? 0x00 : decoded[7];
        if (decoded[3] != static_cast<uint8_t>(conf.id & 0xFF)) return false;
        if (decoded[4] != static_cast<uint8_t>((conf.id >> 8) & 0xF0)) return false;
    }

    return true;
}

std::vector<uint8_t> FanLampEncoderV1::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                          const BleAdvConfig& conf) {
    bool is_pair = (enc_cmd.cmd == 0x28);

    uint16_t group_uid = static_cast<uint16_t>(conf.id & 0xF0FFu)
                       | static_cast<uint16_t>((conf.index & 0x0Fu) << 8);
    uint8_t seed8  = static_cast<uint8_t>(conf.seed & 0xFF);
    uint8_t id_hi  = static_cast<uint8_t>((conf.id >> 16) & 0xFF);

    // Build the 12-byte block that inner CRC is computed over.
    std::vector<uint8_t> obuf;
    obuf.reserve(14);
    obuf.push_back(enc_cmd.cmd);
    obuf.push_back(static_cast<uint8_t>(group_uid & 0xFF));
    obuf.push_back(static_cast<uint8_t>((group_uid >> 8) & 0xFF));
    obuf.push_back(is_pair ? static_cast<uint8_t>(conf.id & 0xFF) : enc_cmd.arg0);
    obuf.push_back(is_pair ? static_cast<uint8_t>((conf.id >> 8) & 0xF0) : enc_cmd.arg1);
    obuf.push_back(_get_arg2(enc_cmd.cmd, enc_cmd.arg2));
    obuf.push_back(conf.tx_count);

    // param: use header[0] for pair when _arg2 == 0, otherwise enc_cmd.param.
    uint8_t param = (is_pair && _arg2 == 0x00) ? _header[0] : enc_cmd.param;
    obuf.push_back(param);

    uint8_t r1 = _xor1 ? (seed8 ^ 1u) : static_cast<uint8_t>(seed8 ^ id_hi);
    uint8_t r2 = _xor1 ? (seed8 ^ 1u) : seed8;
    obuf.push_back(r1);
    obuf.push_back(r2);
    obuf.push_back(static_cast<uint8_t>(conf.seed & 0xFF));
    obuf.push_back(static_cast<uint8_t>((conf.seed >> 8) & 0xFF));

    // Append inner CRC over the 12-byte block.
    std::vector<uint8_t> crc_input(obuf.begin(), obuf.begin() + 12);
    uint16_t crc = _crc16(crc_input, conf.seed ^ 0xFFFFu);
    obuf.push_back(static_cast<uint8_t>(crc & 0xFF));
    obuf.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));

    return obuf;
}

// ─── FanLampEncoderV1aa ──────────────────────────────────────────────────────

Codec& FanLampEncoderV1aa::header(std::vector<uint8_t> hdr, int start_pos) {
    // Use the 9-byte extended PREFIX instead of the 8-byte base PREFIX.
    std::vector<uint8_t> pfx(PREFIX_AA, PREFIX_AA + sizeof(PREFIX_AA));
    auto whitened = whiten(reverse_all(pfx), 0x6F);
    hdr.insert(hdr.end(), whitened.begin(), whitened.end());
    _header           = std::move(hdr);
    _header_start_pos = start_pos;
    _len -= static_cast<int>(sizeof(PREFIX_AA));
    return *this;
}

std::optional<std::vector<uint8_t>> FanLampEncoderV1aa::decrypt(
        const std::vector<uint8_t>& buffer) {
    auto decoded = reverse_all(whiten(buffer, 0x2B));
    if (decoded.empty() || decoded.back() != 0xAA) return std::nullopt;
    decoded.pop_back();
    return decoded;
}

std::vector<uint8_t> FanLampEncoderV1aa::encrypt(const std::vector<uint8_t>& decoded) {
    std::vector<uint8_t> with_aa(decoded);
    with_aa.push_back(0xAA);
    return whiten(reverse_all(with_aa), 0x2B);
}

// ─── FanLampEncoderV2 ────────────────────────────────────────────────────────

FanLampEncoderV2::FanLampEncoderV2(uint16_t device_type, bool with_sign)
    : _device_type(device_type), _with_sign(with_sign) {
    _seed_max = 0xFFF5;
}

std::vector<uint8_t> FanLampEncoderV2::_whiten(const std::vector<uint8_t>& buf,
                                                 uint8_t seed) const {
    // salt distinguishes sub-slots: (prefix[1] & 0x3) << 5.
    uint8_t salt = static_cast<uint8_t>((_prefix.size() > 1 ? (_prefix[1] & 0x3u) : 0u) << 5);
    std::vector<uint8_t> out;
    out.reserve(buf.size());
    for (size_t i = 0; i < buf.size(); i++) {
        uint8_t idx = static_cast<uint8_t>(((seed + i + 9) & 0x1Fu) + salt);
        out.push_back(XBOXES[idx] ^ seed ^ buf[i]);
    }
    return out;
}

uint16_t FanLampEncoderV2::_sign(const std::vector<uint8_t>& buf,
                                   uint8_t tx_count, uint16_t seed) const {
    uint8_t key[16] = {
        static_cast<uint8_t>(seed & 0xFF),
        static_cast<uint8_t>((seed >> 8) & 0xFF),
        tx_count,
        0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    uint8_t plaintext[16] = {};
    for (size_t i = 0; i < 16 && i < buf.size(); i++) {
        plaintext[i] = buf[i];
    }

    uint8_t ciphertext[16] = {};
    esp_aes_context ctx;
    esp_aes_init(&ctx);
    esp_aes_setkey(&ctx, key, 128);
    esp_aes_crypt_ecb(&ctx, ESP_AES_ENCRYPT, plaintext, ciphertext);
    esp_aes_free(&ctx);

    uint16_t sign = static_cast<uint16_t>(ciphertext[0])
                  | (static_cast<uint16_t>(ciphertext[1]) << 8);
    return (sign != 0) ? sign : 0xFFFF;
}

std::optional<std::vector<uint8_t>> FanLampEncoderV2::decrypt(
        const std::vector<uint8_t>& buffer) {
    // buffer must be exactly 24 bytes.
    if (buffer.size() != 24) return std::nullopt;

    uint16_t seed    = static_cast<uint16_t>(buffer[20]) | (static_cast<uint16_t>(buffer[21]) << 8);
    uint16_t crc_msg = static_cast<uint16_t>(buffer[22]) | (static_cast<uint16_t>(buffer[23]) << 8);

    // Outer CRC16-CCITT over bytes 0..21.
    std::vector<uint8_t> crc_input(buffer.begin(), buffer.begin() + 22);
    if (_crc16(crc_input, seed ^ 0xFFFFu) != crc_msg) return std::nullopt;

    // Unwhiten bytes 2..18 (17 bytes); bytes 0..1 pass through unmodified.
    std::vector<uint8_t> inner(buffer.begin() + 2, buffer.begin() + 19);
    auto unwhitened = _whiten(inner, static_cast<uint8_t>(seed & 0xFF));

    // decoded_base = buffer[0:2] ++ unwhitened  (19 bytes)
    std::vector<uint8_t> decoded_base = {buffer[0], buffer[1]};
    decoded_base.insert(decoded_base.end(), unwhitened.begin(), unwhitened.end());

    // Sign lives in decoded_base[17:19].
    uint16_t sign = static_cast<uint16_t>(decoded_base[17])
                  | (static_cast<uint16_t>(decoded_base[18]) << 8);

    if (_with_sign) {
        // Verify AES-ECB sign over decoded_base[1:17] (16 bytes).
        std::vector<uint8_t> sign_input(decoded_base.begin() + 1, decoded_base.begin() + 17);
        if (_sign(sign_input, decoded_base[3], seed) != sign) return std::nullopt;
    } else {
        if (sign != 0) return std::nullopt;
    }

    // Return decoded_base[0:17] ++ seed (2 bytes) — seed artificially appended.
    std::vector<uint8_t> result(decoded_base.begin(), decoded_base.begin() + 17);
    result.push_back(buffer[20]);
    result.push_back(buffer[21]);
    return result;
}

std::vector<uint8_t> FanLampEncoderV2::encrypt(const std::vector<uint8_t>& decoded) {
    // decoded = prefix(3) + content(14) + seed(2) = 19 bytes.
    if (decoded.size() < 2) return {};

    uint16_t seed = static_cast<uint16_t>(decoded[decoded.size() - 2])
                  | (static_cast<uint16_t>(decoded[decoded.size() - 1]) << 8);

    // Drop the seed tail; keep the first (N-2) bytes.
    std::vector<uint8_t> obuf(decoded.begin(), decoded.end() - 2);

    // Append AES-ECB sign (or 0x0000 if with_sign is false).
    uint16_t sign = 0;
    if (_with_sign) {
        std::vector<uint8_t> sign_input(obuf.begin() + 1, obuf.begin() + 17);
        sign = _sign(sign_input, obuf[3], seed);
    }
    obuf.push_back(static_cast<uint8_t>(sign & 0xFF));
    obuf.push_back(static_cast<uint8_t>((sign >> 8) & 0xFF));

    // Append reserved 0x00 byte (becomes buffer[-5] in decrypt).
    obuf.push_back(0x00);

    // Whiten bytes 2..end; bytes 0..1 remain unmodified.
    std::vector<uint8_t> to_whiten(obuf.begin() + 2, obuf.end());
    auto whitened = _whiten(to_whiten, static_cast<uint8_t>(seed & 0xFF));

    std::vector<uint8_t> out = {obuf[0], obuf[1]};
    out.insert(out.end(), whitened.begin(), whitened.end());

    // Append seed (LE16).
    out.push_back(static_cast<uint8_t>(seed & 0xFF));
    out.push_back(static_cast<uint8_t>((seed >> 8) & 0xFF));

    // Append CRC16-CCITT over the 22 bytes built so far.
    uint16_t crc = _crc16(out, seed ^ 0xFFFFu);
    out.push_back(static_cast<uint8_t>(crc & 0xFF));
    out.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));

    return out;
}

bool FanLampEncoderV2::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // decoded is 16 bytes: content(14) + seed(2).
    if (decoded.size() < 16) return false;

    // Verify device type at decoded[1:3].
    uint16_t dt = static_cast<uint16_t>(decoded[1]) | (static_cast<uint16_t>(decoded[2]) << 8);
    if (dt != _device_type) return false;

    conf.seed     = static_cast<uint16_t>(decoded[14]) | (static_cast<uint16_t>(decoded[15]) << 8);
    conf.tx_count = decoded[0];
    conf.id       = static_cast<uint32_t>(decoded[3])
                  | (static_cast<uint32_t>(decoded[4]) << 8)
                  | (static_cast<uint32_t>(decoded[5]) << 16)
                  | (static_cast<uint32_t>(decoded[6]) << 24);
    conf.index    = decoded[7];

    enc_cmd       = BleAdvEncCmd{};
    enc_cmd.cmd   = decoded[8];
    // decoded[9] is reserved (0).
    enc_cmd.param = decoded[10];
    enc_cmd.arg0  = decoded[11];
    enc_cmd.arg1  = decoded[12];
    enc_cmd.arg2  = decoded[13];

    return true;
}

std::vector<uint8_t> FanLampEncoderV2::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                          const BleAdvConfig& conf) {
    // Returns 16 bytes: tx_count | dt(2) | uid(4) | index | cmd | 0 | param | arg0..2 | seed(2)
    return {
        conf.tx_count,
        static_cast<uint8_t>(_device_type & 0xFF),
        static_cast<uint8_t>((_device_type >> 8) & 0xFF),
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>((conf.id >> 16) & 0xFF),
        static_cast<uint8_t>((conf.id >> 24) & 0xFF),
        conf.index,
        enc_cmd.cmd,
        0x00, // reserved
        enc_cmd.param,
        enc_cmd.arg0,
        enc_cmd.arg1,
        enc_cmd.arg2,
        static_cast<uint8_t>(conf.seed & 0xFF),
        static_cast<uint8_t>((conf.seed >> 8) & 0xFF),
    };
}

// ─── FanLampEncoderV2::make_light_cw_cmd ─────────────────────────────────

BleAdvEncCmd FanLampEncoderV2::make_light_cw_cmd(uint8_t cold, uint8_t warm) const {
    BleAdvEncCmd cmd;
    cmd.cmd  = 0x21;
    cmd.arg0 = 0x00;
    cmd.arg1 = cold;
    cmd.arg2 = warm;
    return cmd;
}

// ─── FanLampEncoderV1::get_supported_features ─────────────────────────────

std::vector<SupportedFeature> FanLampEncoderV1::get_supported_features() const {
    std::vector<SupportedFeature> features;

    // Fan speed control: 3 speeds
    SupportedFeature fan_speed;
    fan_speed.feature_name = "fan_speed";
    fan_speed.values = {
        {"speed_off", BleAdvEncCmd(0x31, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"speed_1", BleAdvEncCmd(0x31, 0x00, 0x01, 0x00, 0x00, 0x00)},
        {"speed_2", BleAdvEncCmd(0x31, 0x00, 0x02, 0x00, 0x00, 0x00)},
        {"speed_3", BleAdvEncCmd(0x31, 0x00, 0x03, 0x00, 0x00, 0x00)},
    };
    features.push_back(fan_speed);

    // Direction control
    SupportedFeature direction;
    direction.feature_name = "direction";
    direction.values = {
        {"forward", BleAdvEncCmd(0x15, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"reverse", BleAdvEncCmd(0x15, 0x00, 0x01, 0x00, 0x00, 0x00)},
    };
    features.push_back(direction);

    // Oscillation control
    SupportedFeature oscillation;
    oscillation.feature_name = "oscillation";
    oscillation.values = {
        {"off", BleAdvEncCmd(0x16, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"on", BleAdvEncCmd(0x16, 0x00, 0x01, 0x00, 0x00, 0x00)},
    };
    features.push_back(oscillation);

    // Light control
    SupportedFeature light;
    light.feature_name = "light";
    light.values = {
        {"off", BleAdvEncCmd(0x11, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"on", BleAdvEncCmd(0x10, 0x00, 0x00, 0x00, 0x00, 0x00)},
    };
    features.push_back(light);

    // Cold/warm brightness: param=0x00, arg0=cold(0-255), arg1=warm(0-255)
    // Use via /device/{id}/light_cw/{cold}-{warm}
    SupportedFeature light_cw;
    light_cw.feature_name = "light_cw";
    light_cw.values = {
        {"255-0",   BleAdvEncCmd(0x21, 0x00, 0xFF, 0x00, 0x00, 0x00)}, // cool white
        {"255-255", BleAdvEncCmd(0x21, 0x00, 0xFF, 0xFF, 0x00, 0x00)}, // neutral
        {"0-255",   BleAdvEncCmd(0x21, 0x00, 0x00, 0xFF, 0x00, 0x00)}, // warm white
    };
    features.push_back(light_cw);

    // Pairing
    SupportedFeature pairing;
    pairing.feature_name = "pairing";
    pairing.values = {
        {"pair", BleAdvEncCmd(0x28, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"unpair", BleAdvEncCmd(0x45, 0x00, 0x00, 0x00, 0x00, 0x00)},
    };
    features.push_back(pairing);

    return features;
}

// ─── FanLampEncoderV2::get_supported_features ─────────────────────────────

std::vector<SupportedFeature> FanLampEncoderV2::get_supported_features() const {
    std::vector<SupportedFeature> features;

    // Fan speed control: 6 speeds
    SupportedFeature fan_speed;
    fan_speed.feature_name = "fan_speed";
    fan_speed.values = {
        {"speed_off", BleAdvEncCmd(0x31, 0x00, 0x20, 0x00, 0x00, 0x00)},
        {"speed_1", BleAdvEncCmd(0x31, 0x00, 0x20, 0x01, 0x00, 0x00)},
        {"speed_2", BleAdvEncCmd(0x31, 0x00, 0x20, 0x02, 0x00, 0x00)},
        {"speed_3", BleAdvEncCmd(0x31, 0x00, 0x20, 0x03, 0x00, 0x00)},
        {"speed_4", BleAdvEncCmd(0x31, 0x00, 0x20, 0x04, 0x00, 0x00)},
        {"speed_5", BleAdvEncCmd(0x31, 0x00, 0x20, 0x05, 0x00, 0x00)},
        {"speed_6", BleAdvEncCmd(0x31, 0x00, 0x20, 0x06, 0x00, 0x00)},
    };
    features.push_back(fan_speed);

    // Direction control
    SupportedFeature direction;
    direction.feature_name = "direction";
    direction.values = {
        {"forward", BleAdvEncCmd(0x15, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"reverse", BleAdvEncCmd(0x15, 0x00, 0x01, 0x00, 0x00, 0x00)},
    };
    features.push_back(direction);

    // Oscillation control
    SupportedFeature oscillation;
    oscillation.feature_name = "oscillation";
    oscillation.values = {
        {"off", BleAdvEncCmd(0x16, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"on", BleAdvEncCmd(0x16, 0x00, 0x01, 0x00, 0x00, 0x00)},
    };
    features.push_back(oscillation);

    // Light control
    SupportedFeature light;
    light.feature_name = "light";
    light.values = {
        {"off", BleAdvEncCmd(0x11, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"on", BleAdvEncCmd(0x10, 0x00, 0x00, 0x00, 0x00, 0x00)},
    };
    features.push_back(light);

    // Cold/warm brightness: arg0=0x00(flag), arg1=cold(0-255), arg2=warm(0-255)
    // Use via /device/{id}/light_cw/{cold}-{warm}
    SupportedFeature light_cw;
    light_cw.feature_name = "light_cw";
    light_cw.values = {
        {"255-0",   BleAdvEncCmd(0x21, 0x00, 0x00, 0xFF, 0x00, 0x00)}, // cool white
        {"255-255", BleAdvEncCmd(0x21, 0x00, 0x00, 0xFF, 0xFF, 0x00)}, // neutral
        {"0-255",   BleAdvEncCmd(0x21, 0x00, 0x00, 0x00, 0xFF, 0x00)}, // warm white
    };
    features.push_back(light_cw);

    // Pairing
    SupportedFeature pairing;
    pairing.feature_name = "pairing";
    pairing.values = {
        {"pair", BleAdvEncCmd(0x28, 0x00, 0x00, 0x00, 0x00, 0x00)},
        {"unpair", BleAdvEncCmd(0x45, 0x00, 0x00, 0x00, 0x00, 0x00)},
    };
    features.push_back(pairing);

    return features;
}

std::vector<fanesp::Codec*> get_fanlamp_codecs() {
    static FanLampEncoderV1 codec_flv1(0x83, false);
    static FanLampEncoderV2 codec_flv2(0x0400, false);
    static FanLampEncoderV2 codec_flv3(0x0400, true);
    static FanLampEncoderV2 codec_flv3s1(0x0400, true);
    static FanLampEncoderV2 codec_flv3s2(0x0400, true);
    static FanLampEncoderV2 codec_flv3s3(0x0400, true);
    static FanLampEncoderV1 codec_lsv1(0x81, true);
    static FanLampEncoderV2 codec_lsv2(0x0100, false);
    static FanLampEncoderV2 codec_lsv3(0x0100, true);
    static FanLampEncoderV1aa codec_lsvi1(0x81, true, false);
    static FanLampEncoderV1R0 codec_flv1r0;
    static FanLampEncoderV1R1 codec_flv1r1;

    static bool configured = false;
    if (!configured) {
        codec_flv1.header({0x77, 0xF8}).ble(0x19, 0x03);
        codec_flv2.header({0xF0, 0x08}).prefix({0x10, 0x80, 0x00}).ble(0x19, 0x03);
        codec_flv3.header({0xF0, 0x08}).prefix({0x20, 0x80, 0x00}).ble(0x19, 0x03);
        codec_flv3s1.header({0xF0, 0x08}).prefix({0x20, 0x81, 0x00}).ble(0x19, 0x03);
        codec_flv3s2.header({0xF0, 0x08}).prefix({0x20, 0x82, 0x00}).ble(0x19, 0x03);
        codec_flv3s3.header({0xF0, 0x08}).prefix({0x20, 0x83, 0x00}).ble(0x19, 0x03);
        codec_lsv1.header({0x77, 0xF8}).ble(0x19, 0x03);
        codec_lsv2.header({0xF0, 0x08}).prefix({0x10, 0x80, 0x00}).ble(0x19, 0x03);
        codec_lsv3.header({0xF0, 0x08}).prefix({0x30, 0x80, 0x00}).ble(0x19, 0x03);
        codec_lsvi1.header({0xF9, 0x08}).ble(0x19, 0x03);
        codec_flv1r0.header({0xF0, 0xFF}).ble(0x19, 0xFF);
        codec_flv1r1.header({0xF0, 0xFF}).ble(0x19, 0xFF);
        configured = true;
    }

    return {&codec_flv1,  &codec_flv2,   &codec_flv3,   &codec_flv3s1,
            &codec_flv3s2, &codec_flv3s3, &codec_lsv1,   &codec_lsv2,
            &codec_lsv3,   &codec_lsvi1,  &codec_flv1r0, &codec_flv1r1};
}

} // namespace fanesp::codecs
