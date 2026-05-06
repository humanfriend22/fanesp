#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

/**
 * RW.Light encoder. Complex XOR scramble + whiten + CRC16-CCITT(seed=0x696B).
 * 18-byte packet, 11-byte logical payload.
 */
class RwEncoder : public Codec {
public:
    RwEncoder() { _len = 18; _seed_max = 0xF5; }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x0B; }
};

std::vector<Codec*> get_rw_codecs();

} // namespace fanesp::codecs
