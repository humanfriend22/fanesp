#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fanesp {

/**
 * @brief Codec-level command carrying all command fields extracted from a packet.
 *
 * Populated by convert_to_enc() from the decrypted payload and consumed by
 * convert_from_enc() when encoding.
 */
struct BleAdvEncCmd {
    uint8_t cmd   = 0; ///< Primary command byte.
    uint8_t param = 0; ///< Command sub-parameter.
    uint8_t arg0  = 0; ///< Argument 0.
    uint8_t arg1  = 0; ///< Argument 1.
    uint8_t arg2  = 0; ///< Argument 2.
    uint8_t arg3  = 0; ///< Argument 3.
    uint8_t arg4  = 0; ///< Argument 4.
};

/**
 * @brief Per-device session configuration passed alongside every command.
 *
 * Persisted between calls: tx_count and seed are updated in-place by encode_advs().
 */
struct BleAdvConfig {
    uint32_t id                = 0; ///< Device identifier (codec-dependent width up to 32 bits).
    uint32_t aux_id            = 0; ///< Codec-specific extra identity (e.g. ZhiJia MAC, lower 24 bits).
    uint8_t  index             = 0; ///< Group / channel index within a device.
    uint8_t  tx_count          = 0; ///< Rolling transmit counter (wraps at _tx_max).
    uint8_t  app_restart_count = 1; ///< Incremented when tx_count wraps.
    uint16_t seed              = 0; ///< Per-session random seed (0 = not yet initialised).

    /** @return Stable hex string identifier, e.g. "B1825C36:0". */
    std::string device_id() const {
        char buf[13];
        snprintf(buf, sizeof(buf), "%08lX:%u", (unsigned long)id, index);
        return std::string(buf);
    }

    bool operator==(const BleAdvConfig &o) const { return id == o.id && index == o.index; }
    bool operator!=(const BleAdvConfig &o) const { return !(*this == o); }
};

/**
 * @brief A parsed BLE advertisement with primary and optional secondary AD records.
 *
 * The BLE advertisement data is a sequence of TLV records:
 *   [ length (1) | type (1) | data (length-1) ] ...
 *
 * Only types 0x03, 0x05, 0x07, 0x16, and 0xFF are recognised; the first match is
 * the primary record, the second match (if any) is the secondary record.
 */
struct BleAdvAdvertisement {
    uint8_t              ble_type    = 0x00; ///< Primary AD type byte.
    std::vector<uint8_t> raw;                ///< Primary AD payload (type byte excluded).
    uint8_t              ad_flag     = 0x00; ///< AD Flags byte prepended by to_raw() when non-zero.
    uint8_t              second_type = 0x00; ///< Secondary AD type (0 if absent).
    std::optional<std::vector<uint8_t>> second_raw; ///< Secondary AD payload.

    /**
     * @brief Parse raw BLE advertisement data into a BleAdvAdvertisement.
     *
     * Iterates TLV records. The first record whose type is in {0x03,0x05,0x07,0x16,0xFF}
     * becomes the primary (ble_type / raw). The next such record becomes the secondary.
     * Falls back to treating the entire buffer as raw with ble_type=0 if no match is found.
     *
     * @param raw_adv  Full raw advertisement payload.
     * @return         Populated BleAdvAdvertisement.
     */
    static BleAdvAdvertisement from_raw(const std::vector<uint8_t>& raw_adv);

    /**
     * @brief Serialise back to raw BLE advertisement bytes.
     *
     * Prepends [0x02, 0x01, ad_flag] when ad_flag != 0, then the primary TLV record,
     * then the secondary TLV record when present.
     */
    std::vector<uint8_t> to_raw() const;
};

/**
 * @brief Descriptor for a single feature value.
 *
 * Represents one possible command encoding for a feature (e.g., "fan speed 1").
 * Combines a human-readable name with the command encoding.
 */
struct FeatureValue {
    std::string name;      ///< Human-readable name (e.g., "speed_1", "direction_forward").
    BleAdvEncCmd cmd;      ///< Command encoding (cmd, param, arg0-arg3).
};

/**
 * @brief Descriptor for a supported feature and its possible values.
 *
 * Groups all command encodings for a single feature (e.g., "fan_speed" with 3 or 6 speeds).
 */
struct SupportedFeature {
    std::string feature_name;           ///< Feature name (e.g., "fan_speed", "direction").
    std::vector<FeatureValue> values;   ///< Possible values for this feature.
};

/**
 * @brief Abstract base class for all BLE advertisement codecs.
 *
 * Each codec implements four transform methods:
 *   - decrypt()          raw payload → readable buffer (or nullopt on failure)
 *   - encrypt()          readable buffer → raw payload
 *   - convert_to_enc()   readable buffer → BleAdvEncCmd + BleAdvConfig
 *   - convert_from_enc() BleAdvEncCmd + BleAdvConfig → readable buffer
 *
 * The orchestration methods decode_adv() and encode_advs() call these in order,
 * handling header/footer stripping, prefix checking, and counter management.
 *
 * Builder methods (ble(), header(), prefix(), footer()) configure codec parameters
 * and return a Codec& to allow chained calls.
 *
 * Feature discovery method:
 *   - get_supported_features() returns explicit feature descriptors for the codec.
 */
class Codec {
public:
    virtual ~Codec() = default;

    // -------------------------------------------------------------------------
    // Core transform interface – must be implemented by each codec subclass.
    // -------------------------------------------------------------------------

    /**
     * @brief Decrypt a raw payload into a readable (plaintext) buffer.
     *
     * Receives the packet with header and footer already stripped by decode_adv().
     * Performs codec-specific decryption and validates any embedded checksums or
     * fixed-byte markers.
     *
     * @param buffer  Raw payload bytes.
     * @return        Decrypted bytes on success, or nullopt if validation fails.
     */
    virtual std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) = 0;

    /**
     * @brief Encrypt a readable buffer into a raw payload.
     *
     * Receives the prefix-prepended plaintext assembled by encode_advs(). Must
     * produce exactly _len bytes of output.
     *
     * @param decoded  Plaintext buffer (prefix + content from convert_from_enc).
     * @return         Encrypted raw payload bytes.
     */
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) = 0;

    /**
     * @brief Extract BleAdvEncCmd and BleAdvConfig from a decrypted, prefix-stripped buffer.
     *
     * Called by decode_adv() after decrypt() succeeds and the prefix is verified and removed.
     *
     * @param decoded   Decrypted buffer with prefix already removed.
     * @param[out] enc_cmd  Populated command fields.
     * @param[out] conf     Populated config fields.
     * @return              True on success, false if further validation fails.
     */
    virtual bool convert_to_enc(const std::vector<uint8_t>& decoded,
                                 BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) = 0;

    /**
     * @brief Serialise BleAdvEncCmd + BleAdvConfig into a readable buffer.
     *
     * The returned buffer is prefix-stripped; encode_advs() prepends _prefix before
     * calling encrypt().
     *
     * @param enc_cmd  Command to serialise.
     * @param conf     Configuration to serialise.
     * @return         Serialised plaintext bytes.
     */
    virtual std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                    const BleAdvConfig& conf) = 0;

    // -------------------------------------------------------------------------
    // Orchestration
    // -------------------------------------------------------------------------

    /**
     * @brief Full decode pipeline for an incoming advertisement.
     *
     * Steps:
     *   1. Verify ble_type matches _ble_type.
     *   2. Verify payload length equals _len + _header.size() + _header_start_pos.
     *   3. Verify header bytes at _header_start_pos.
     *   4. Verify footer bytes at the tail.
     *   5. Call decrypt() on header-stripped bytes.
     *   6. Verify _prefix at the start of the decrypted buffer.
     *   7. Call convert_to_enc() on the prefix-stripped decrypted buffer.
     *
     * @param adv        Incoming parsed advertisement.
     * @param[out] enc_cmd  Valid only when true is returned.
     * @param[out] conf     Valid only when true is returned.
     * @return             True on success.
     */
    bool decode_adv(const BleAdvAdvertisement& adv, BleAdvEncCmd& enc_cmd, BleAdvConfig& conf);

    /**
     * @brief Full encode pipeline for an outgoing command.
     *
     * Steps:
     *   1. Increment tx_count (wraps at _tx_max, increments app_restart_count on wrap).
     *   2. Generate a random seed in [1, _seed_max] if seed == 0 and _seed_max > 0.
     *   3. Call convert_from_enc() to obtain a plaintext payload.
     *   4. Prepend _prefix and call encrypt().
     *   5. Reinsert _header at _header_start_pos and append _footer.
     *   6. Wrap in a BleAdvAdvertisement with the codec's BLE parameters.
     *
     * @param enc_cmd  Command to encode.
     * @param conf     Config updated in-place (tx_count, seed).
     * @return         List of advertisements to transmit (usually one).
     */
    std::vector<BleAdvAdvertisement> encode_advs(const BleAdvEncCmd& enc_cmd, BleAdvConfig& conf);

    // -------------------------------------------------------------------------
    // Feature Discovery
    // -------------------------------------------------------------------------

    /**
     * @brief Get the features supported by this codec.
     *
     * Returns a list of feature descriptors, each containing possible values
     * and their corresponding command encodings. Callers can query this to
     * understand what commands a codec supports at runtime.
     *
     * @return List of supported features with their values.
     */
    virtual std::vector<SupportedFeature> get_supported_features() const {
        return {};
    }

    /**
     * @brief Build the BleAdvEncCmd for a cold/warm brightness command (cmd=0x21).
     *
     * V1 layout: param=0x00, arg0=cold, arg1=warm.
     * V2 layout: arg0=0x00, arg1=cold, arg2=warm.
     * Default implementation uses the V1 layout; FanLampEncoderV2 overrides for V2.
     *
     * @param cold  Cold-white level (0–255).
     * @param warm  Warm-white level (0–255).
     * @return      Populated BleAdvEncCmd ready for encode_advs().
     */
    virtual BleAdvEncCmd make_light_cw_cmd(uint8_t cold, uint8_t warm) const {
        BleAdvEncCmd cmd;
        cmd.cmd   = 0x21;
        cmd.param = 0x00;
        cmd.arg0  = cold;
        cmd.arg1  = warm;
        return cmd;
    }

    /**
     * @brief Get unique codec identifier.
     *
     * Each codec subclass should return a unique ID to identify itself.
     * Used for device persistence — the codec ID is stored with device config
     * so that the correct codec can be restored when loading from NVS.
     *
     * @return Unique codec identifier.
     */
    virtual uint8_t get_codec_id() const {
        return 0x00;
    }

    // -------------------------------------------------------------------------
    // Builder methods
    // -------------------------------------------------------------------------

    /** @brief Set BLE ad_flag and ble_type for this codec. */
    Codec& ble(uint8_t ad_flag, uint8_t ble_type);

    /**
     * @brief Set the expected header bytes and their start position within the payload.
     *
     * During decode: bytes at [start_pos .. start_pos+header.size()) must match.
     * During encode: the header is reinserted at start_pos after encryption.
     *
     * @param hdr       Header byte sequence.
     * @param start_pos Byte offset within the payload where the header begins (default 0).
     */
    virtual Codec& header(std::vector<uint8_t> hdr, int start_pos = 0);

    /**
     * @brief Set the expected prefix at the start of the decrypted payload.
     *
     * Verified after decrypt() and stripped before convert_to_enc().
     * Prepended before convert_from_enc() output before encrypt().
     */
    Codec& prefix(std::vector<uint8_t> pfx);

    /** @brief Set footer bytes appended after the encrypted payload (verified on decode). */
    Codec& footer(std::vector<uint8_t> ftr);

protected:
    int _len              = 0;   ///< Expected encrypted payload size (excluding header/footer).
    int _tx_step          = 1;   ///< Amount added to tx_count per encode call.
    int _tx_max           = 125; ///< tx_count wraps modulo this value.
    int _seed_max         = 0;   ///< Upper bound for random seed (0 disables seeding).

    uint8_t second_type = 0x00;                      ///< Secondary AD type written into encoded advs.
    std::optional<std::vector<uint8_t>> second_raw;  ///< Secondary AD payload written into encoded advs.

    std::vector<uint8_t> _header;
    int                  _header_start_pos = 0;
    std::vector<uint8_t> _prefix;
    std::vector<uint8_t> _footer;
    uint8_t              _ble_type         = 0x00;
    uint8_t              _ad_flag          = 0x00;
};

} // namespace fanesp
