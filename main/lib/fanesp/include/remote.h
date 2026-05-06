#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

/**
 * Generic physical remote encoder (simple checksum, 8-byte packet).
 * Matches the "remotes" codec family from ha-ble-adv.
 */
class RemoteEncoder : public Codec {
public:
    RemoteEncoder() { _len = 8; }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x06; }
};

std::vector<Codec*> get_remote_codecs();

} // namespace fanesp::codecs
