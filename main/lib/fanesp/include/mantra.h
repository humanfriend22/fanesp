#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

/**
 * Mantra Lighting encoder. 18-byte packet with 16-bit LFSR whitening.
 * The seed for whitening comes from bytes [2:4] of the payload (big-endian tx counter).
 */
class MantraEncoder : public Codec {
public:
    MantraEncoder() { _len = 18; _tx_max = 0x0FFF; }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x0C; }

private:
    static const uint8_t FAMILY[4];
};

std::vector<Codec*> get_mantra_codecs();

} // namespace fanesp::codecs
