#pragma once

#include "ble_adv_codec.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <optional>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

/** BLE device record persisted to NVS. */
struct PersistentDevice {
    uint8_t mac[6];   ///< Device MAC address (little-endian)
    uint8_t codec_id; ///< Codec used to communicate with this device
    fanesp::BleAdvConfig conf;

    /** @return Colon-separated MAC string (e.g. "AA:BB:CC:DD:EE:FF"). */
    std::string mac_str() const {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", mac[5], mac[4], mac[3],
                 mac[2], mac[1], mac[0]);
        return std::string(buf);
    }
};

/**
 * Controls BLE fan/light devices via advertisement-based commands.
 *
 * Manages device discovery, NVS persistence, and command dispatch.
 * All public methods are safe to call from any FreeRTOS task.
 */
class DeviceController {
    friend int discovery_scan_callback(struct ble_gap_event *event, void *arg);

public:
    DeviceController();

    /**
     * Scan for a compatible BLE device.
     *
     * Blocks for up to @p duration_ms milliseconds. Returns early if a device
     * is found. The discovered device is automatically saved to NVS.
     *
     * @param duration_ms Maximum scan duration in milliseconds.
     * @return The first discovered device, or nullopt if none found.
     */
    std::optional<PersistentDevice> discover_device(int duration_ms);

    /**
     * Load all devices previously saved to NVS into memory.
     *
     * @return Vector of loaded devices (also stored internally).
     */
    std::vector<PersistentDevice> load_devices();

    /** @return Read-only reference to the in-memory device list. */
    const std::vector<PersistentDevice> &get_devices() const { return _discovered_devices; }

    /**
     * Toggle the light on a device.
     *
     * @param device_id Index into the discovered devices list.
     * @param on        True to turn on, false to turn off.
     * @return True if the BLE advertisement was transmitted successfully.
     */
    bool light(size_t device_id, bool on);

    /**
     * Set the fan speed on a device.
     *
     * @param device_id Index into the discovered devices list.
     * @param speed     Speed level (0 = off, 1–N = speed steps supported by the codec).
     * @return True if the BLE advertisement was transmitted successfully.
     */
    bool fan(size_t device_id, int speed);

    /**
     * Set cold/warm brightness on a device's light (cmd=0x21).
     *
     * @param device_id Index into the discovered devices list.
     * @param cold      Cold-white level (0–255). 0 = off, 255 = maximum.
     * @param warm      Warm-white level (0–255). 0 = off, 255 = maximum.
     * @return True if the BLE advertisement was transmitted successfully.
     */
    bool light_cw(size_t device_id, int cold, int warm);

    /**
     * Execute a named feature value on a device.
     *
     * Looks up @p feature and @p value in the codec's supported feature list and
     * transmits the corresponding command. Works for any feature exposed by
     * get_supported_features() (e.g. "light"/"on", "fan_speed"/"speed_2").
     *
     * @param device_id Index into the discovered devices list.
     * @param feature   Feature name (e.g. "light", "fan_speed").
     * @param value     Value name (e.g. "on", "speed_3").
     * @return True if the BLE advertisement was transmitted successfully.
     */
    bool execute(size_t device_id, const std::string &feature, const std::string &value);

private:
    std::vector<PersistentDevice> _discovered_devices;
    fanesp::Codec *_codecs[12];
    size_t _codecs_count;
    std::optional<PersistentDevice> _last_discovered_device;
    EventGroupHandle_t _discovery_event;

    /** @return Index of device with matching conf (id + index), or -1 if not found. */
    int find_device_by_id(const fanesp::BleAdvConfig &conf);

    /** Encode and transmit all advertisements for a single command. */
    bool send_command(fanesp::Codec *codec, fanesp::BleAdvConfig &conf,
                      const fanesp::BleAdvEncCmd &enc_cmd);

    /** Persist a single device record to NVS at the given index. */
    void save_device_to_nvs(const PersistentDevice &device, size_t index);

    /** Rewrite all in-memory devices to NVS (used after removal). */
    void sync_devices_to_nvs();
};
