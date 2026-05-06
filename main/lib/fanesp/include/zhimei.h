#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

class ZhimeiEncoderV0 : public Codec {
public:
    ZhimeiEncoderV0() { _len = 9; }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x0D; }
};

class ZhimeiEncoderV1 : public Codec {
public:
    ZhimeiEncoderV1() {
        _len      = 16;
        _seed_max = 0xF5;
        footer({0x10, 0x11, 0x12, 0x13, 0x14, 0x15});
    }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x0E; }
};

class ZhimeiEncoderV2 : public Codec {
public:
    ZhimeiEncoderV2() {
        _len = 13;
        footer({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19});
    }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x0F; }
};

std::vector<Codec*> get_zhimei_codecs();

} // namespace fanesp::codecs
