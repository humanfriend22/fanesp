#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

/**
 * RuiXin encoder. 16-byte packet with additive-cipher obfuscation.
 * Seed byte at [0] is added to (and subtracted from) each subsequent byte.
 */
class RuiXinEncoder : public Codec {
public:
    RuiXinEncoder() { _len = 16; _seed_max = 0xF5; }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x08; }
};

std::vector<Codec*> get_ruixin_codecs();

} // namespace fanesp::codecs
