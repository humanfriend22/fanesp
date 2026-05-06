#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>

#include "include/device_controller.h"
#include "include/config.h"
#include "codecs.h"

#include <cstring>
#include <esp_log.h>
#include <host/ble_gap.h>
#include <nvs.h>
#include <nvs_flash.h>

static const char *TAG = "device_ctrl";

static fanesp::Codec **temp_codecs = nullptr;
static size_t temp_codecs_count = 0;
static DeviceController *temp_controller = nullptr;

int discovery_scan_callback(struct ble_gap_event *event, void *arg);

DeviceController::DeviceController() : _codecs_count(0) {
    _discovery_event = xEventGroupCreate();
}

int DeviceController::find_device_by_id(const fanesp::BleAdvConfig &conf) {
    for (size_t i = 0; i < _discovered_devices.size(); i++) {
        if (_discovered_devices[i].conf == conf) {
            return i;
        }
    }
    return -1;
}

std::optional<PersistentDevice> DeviceController::discover_device(int duration_ms) {
    auto fanlamp_codecs = fanesp::codecs::get_all_codecs();

    temp_codecs = fanlamp_codecs.data();
    temp_codecs_count = fanlamp_codecs.size();
    temp_controller = this;
    _last_discovered_device = std::nullopt;

    struct ble_gap_disc_params discovery_params = {
        .itvl = CFG_BLE_SCAN_ITVL,
        .window = CFG_BLE_SCAN_WINDOW,
        .filter_policy = BLE_HCI_SCAN_FILT_NO_WL_INITA,
        .limited = 0,
        .passive = 1,
        .filter_duplicates = 1,
        .disable_observer_mode = 0,
    };

    xEventGroupClearBits(_discovery_event, 0x01);

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, duration_ms, &discovery_params,
                          discovery_scan_callback, nullptr);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
        return std::nullopt;
    }

    ESP_LOGI(TAG, "BLE scan started (duration: %d ms)", duration_ms);

    EventBits_t bits = xEventGroupWaitBits(_discovery_event, 0x01, pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(duration_ms + 500));  // +500 grace period

    temp_codecs = nullptr;
    temp_codecs_count = 0;
    temp_controller = nullptr;

    if (bits & 0x01) {
        ESP_LOGI(TAG, "Device found, exiting scan early");
    }

    return _last_discovered_device;
}

std::vector<PersistentDevice> DeviceController::load_devices() {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(CFG_NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open failed: %d", err);
        return {};
    }

    uint32_t dev_count = 0;
    err = nvs_get_u32(nvs_handle, "dev_count", &dev_count);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        return {};
    }

    _discovered_devices.clear();
    for (uint32_t i = 0; i < dev_count; i++) {
        char key[16];
        snprintf(key, sizeof(key), "dev_%lu", (unsigned long)i);
        size_t len = sizeof(PersistentDevice);
        PersistentDevice device = {};
        err = nvs_get_blob(nvs_handle, key, &device, &len);
        if (err != ESP_OK || len != sizeof(PersistentDevice)) {
            ESP_LOGW(TAG, "Skipping stale device %u (blob size %zu != expected %zu)", i, len,
                     sizeof(PersistentDevice));
            continue;
        }

        int existing = find_device_by_id(device.conf);
        if (existing >= 0) {
            _discovered_devices[existing] = device;
            ESP_LOGW(TAG, "Deduped device %u: id=0x%08lX (replaced index %d)", i,
                     device.conf.id, existing);
        } else {
            _discovered_devices.push_back(device);
            ESP_LOGI(TAG, "Loaded device %u: id=0x%08lX codec_id=0x%02X", i, device.conf.id,
                     device.codec_id);
        }
    }

    nvs_close(nvs_handle);

    if (_discovered_devices.size() != dev_count) {
        ESP_LOGI(TAG, "Deduped %lu → %zu devices, syncing NVS",
                 (unsigned long)dev_count, _discovered_devices.size());
        sync_devices_to_nvs();
    }

    return _discovered_devices;
}

bool DeviceController::light(size_t device_id, bool on) {
    if (device_id >= _discovered_devices.size()) {
        ESP_LOGE(TAG, "Invalid device_id: %zu", device_id);
        return false;
    }

    PersistentDevice &device = _discovered_devices[device_id];
    auto fanlamp_codecs = fanesp::codecs::get_all_codecs();

    fanesp::Codec *codec = nullptr;
    for (size_t i = 0; i < fanlamp_codecs.size(); i++) {
        if (fanlamp_codecs[i]->get_codec_id() == device.codec_id) {
            codec = fanlamp_codecs[i];
            break;
        }
    }

    if (!codec) {
        ESP_LOGW(TAG, "Codec 0x%02X not available, removing stale device", device.codec_id);
        _discovered_devices.erase(_discovered_devices.begin() + device_id);
        sync_devices_to_nvs();
        return false;
    }

    auto features = codec->get_supported_features();
    for (const auto &feature : features) {
        if (feature.feature_name == "light") {
            for (const auto &value : feature.values) {
                if ((on && value.name == "on") || (!on && value.name == "off")) {
                    return send_command(codec, device.conf, value.cmd);
                }
            }
            ESP_LOGW(TAG, "light %s value not found", on ? "on" : "off");
            return false;
        }
    }

    ESP_LOGW(TAG, "light feature not found");
    return false;
}

bool DeviceController::fan(size_t device_id, int speed) {
    if (device_id >= _discovered_devices.size()) {
        ESP_LOGE(TAG, "Invalid device_id: %zu", device_id);
        return false;
    }

    PersistentDevice &device = _discovered_devices[device_id];
    auto fanlamp_codecs = fanesp::codecs::get_all_codecs();

    fanesp::Codec *codec = nullptr;
    for (size_t i = 0; i < fanlamp_codecs.size(); i++) {
        if (fanlamp_codecs[i]->get_codec_id() == device.codec_id) {
            codec = fanlamp_codecs[i];
            break;
        }
    }

    if (!codec) {
        ESP_LOGW(TAG, "Codec 0x%02X not available, removing stale device", device.codec_id);
        _discovered_devices.erase(_discovered_devices.begin() + device_id);
        sync_devices_to_nvs();
        return false;
    }

    auto features = codec->get_supported_features();
    for (const auto &feature : features) {
        if (feature.feature_name == "fan_speed") {
            for (const auto &value : feature.values) {
                if (speed == 0 && value.name == "speed_off") {
                    return send_command(codec, device.conf, value.cmd);
                } else if (speed > 0 && value.name == ("speed_" + std::to_string(speed))) {
                    return send_command(codec, device.conf, value.cmd);
                }
            }
            ESP_LOGW(TAG, "fan_speed value %d not found", speed);
            return false;
        }
    }

    ESP_LOGW(TAG, "fan_speed feature not found");
    return false;
}

bool DeviceController::execute(size_t device_id, const std::string &feature,
                               const std::string &value) {
    if (device_id >= _discovered_devices.size()) {
        ESP_LOGE(TAG, "Invalid device_id: %zu", device_id);
        return false;
    }

    PersistentDevice &device = _discovered_devices[device_id];
    auto fanlamp_codecs = fanesp::codecs::get_all_codecs();

    fanesp::Codec *codec = nullptr;
    for (size_t i = 0; i < fanlamp_codecs.size(); i++) {
        if (fanlamp_codecs[i]->get_codec_id() == device.codec_id) {
            codec = fanlamp_codecs[i];
            break;
        }
    }

    if (!codec) {
        ESP_LOGW(TAG, "Codec 0x%02X not available, removing stale device", device.codec_id);
        _discovered_devices.erase(_discovered_devices.begin() + device_id);
        sync_devices_to_nvs();
        return false;
    }

    auto features = codec->get_supported_features();
    for (const auto &f : features) {
        if (f.feature_name != feature) continue;
        for (const auto &v : f.values) {
            if (v.name == value) {
                return send_command(codec, device.conf, v.cmd);
            }
        }
        ESP_LOGW(TAG, "Value '%s' not found for feature '%s'", value.c_str(), feature.c_str());
        return false;
    }

    ESP_LOGW(TAG, "Feature '%s' not found", feature.c_str());
    return false;
}

bool DeviceController::light_cw(size_t device_id, int cold, int warm) {
    if (device_id >= _discovered_devices.size()) {
        ESP_LOGE(TAG, "Invalid device_id: %zu", device_id);
        return false;
    }

    PersistentDevice &device = _discovered_devices[device_id];
    auto fanlamp_codecs = fanesp::codecs::get_all_codecs();

    fanesp::Codec *codec = nullptr;
    for (size_t i = 0; i < fanlamp_codecs.size(); i++) {
        if (fanlamp_codecs[i]->get_codec_id() == device.codec_id) {
            codec = fanlamp_codecs[i];
            break;
        }
    }

    if (!codec) {
        ESP_LOGW(TAG, "Codec 0x%02X not available, removing stale device", device.codec_id);
        _discovered_devices.erase(_discovered_devices.begin() + device_id);
        sync_devices_to_nvs();
        return false;
    }

    uint8_t c = (cold < 0) ? 0 : (cold > 255) ? 255 : static_cast<uint8_t>(cold);
    uint8_t w = (warm < 0) ? 0 : (warm > 255) ? 255 : static_cast<uint8_t>(warm);
    auto enc_cmd = codec->make_light_cw_cmd(c, w);
    return send_command(codec, device.conf, enc_cmd);
}

bool DeviceController::send_command(fanesp::Codec *codec, fanesp::BleAdvConfig &conf,
                                    const fanesp::BleAdvEncCmd &enc_cmd) {
    auto advs = codec->encode_advs(enc_cmd, conf);

    for (const auto &adv : advs) {
        auto raw = adv.to_raw();

        struct ble_gap_adv_params params = {};
        params.conn_mode = BLE_GAP_CONN_MODE_NON;
        params.disc_mode = BLE_GAP_DISC_MODE_NON;
        params.itvl_min = CFG_BLE_ADV_ITVL_MIN;
        params.itvl_max = CFG_BLE_ADV_ITVL_MAX;

        int rc = ble_gap_adv_set_data(raw.data(), (int)raw.size());
        if (rc != 0) {
            ESP_LOGE(TAG, "adv_set_data failed: %d", rc);
            return false;
        }

        rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, nullptr, CFG_BLE_ADV_DURATION_MS, &params,
                               nullptr, nullptr);
        if (rc != 0) {
            ESP_LOGE(TAG, "adv_start failed: %d", rc);
            return false;
        }

        vTaskDelay(pdMS_TO_TICKS(CFG_BLE_ADV_DELAY_MS));
        ble_gap_adv_stop();
    }

    ESP_LOGI(TAG, "command sent: cmd=0x%02X", enc_cmd.cmd);
    return true;
}

void DeviceController::save_device_to_nvs(const PersistentDevice &device, size_t index) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(CFG_NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open failed: %d", err);
        return;
    }

    char key[16];
    snprintf(key, sizeof(key), "dev_%zu", index);
    err = nvs_set_blob(nvs_handle, key, &device, sizeof(PersistentDevice));
    if (err == ESP_OK) {
        nvs_set_u32(nvs_handle, "dev_count", index + 1);
        nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Saved device %zu to NVS: id=0x%08lX codec_id=0x%02X", index,
                 device.conf.id, device.codec_id);
    }

    nvs_close(nvs_handle);
}

void DeviceController::sync_devices_to_nvs() {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(CFG_NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open failed: %d", err);
        return;
    }

    for (size_t i = 0; i < _discovered_devices.size(); i++) {
        char key[16];
        snprintf(key, sizeof(key), "dev_%zu", i);
        nvs_set_blob(nvs_handle, key, &_discovered_devices[i], sizeof(PersistentDevice));
    }

    nvs_set_u32(nvs_handle, "dev_count", _discovered_devices.size());
    nvs_commit(nvs_handle);
    ESP_LOGI(TAG, "Synced %zu devices to NVS", _discovered_devices.size());

    nvs_close(nvs_handle);
}

int discovery_scan_callback(struct ble_gap_event *event, void *arg) {
    ESP_LOGD(TAG, "Callback invoked: event type=%d", event->type);

    if (event->type != BLE_GAP_EVENT_DISC || !temp_controller) {
        return 0;
    }

    const struct ble_gap_disc_desc &disc = event->disc;
    if (disc.length_data == 0) {
        return 0;
    }

    ESP_LOGD(TAG, "Advertisement received: len=%d", disc.length_data);

    std::vector<uint8_t> raw_adv(disc.data, disc.data + disc.length_data);
    fanesp::BleAdvAdvertisement adv = fanesp::BleAdvAdvertisement::from_raw(raw_adv);

    for (size_t i = 0; i < temp_codecs_count && temp_codecs; i++) {
        fanesp::BleAdvEncCmd enc_cmd;
        fanesp::BleAdvConfig conf;

        if (!temp_codecs[i]->decode_adv(adv, enc_cmd, conf)) {
            ESP_LOGD(TAG, "Codec 0x%02X decode failed", temp_codecs[i]->get_codec_id());
            continue;
        }

        PersistentDevice device;
        memcpy(device.mac, disc.addr.val, 6);
        device.codec_id = temp_codecs[i]->get_codec_id();
        device.conf = conf;

        ESP_LOGI(TAG, "Found device: addr=%s id=0x%08lX codec=0x%02X tx=%u",
                 device.mac_str().c_str(), conf.id, temp_codecs[i]->get_codec_id(), conf.tx_count);

        int existing_idx = temp_controller->find_device_by_id(conf);
        size_t dev_index;

        if (existing_idx >= 0) {
            dev_index = existing_idx;
            temp_controller->_discovered_devices[dev_index] = device;
            ESP_LOGI(TAG, "Updated device at index %zu", dev_index);
        } else {
            dev_index = temp_controller->_discovered_devices.size();
            temp_controller->_discovered_devices.push_back(device);
            ESP_LOGI(TAG, "Added new device at index %zu", dev_index);
        }

        temp_controller->_last_discovered_device = device;
        temp_controller->save_device_to_nvs(device, dev_index);

        xEventGroupSetBits(temp_controller->_discovery_event, 0x01);
        ble_gap_disc_cancel();
        break;
    }

    return 0;
}
