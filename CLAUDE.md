# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Flash

```bash
idf.py build                        # compile
idf.py -p /dev/ttyUSB0 flash        # flash to ESP32-C6
idf.py -p /dev/ttyUSB0 monitor      # serial monitor
idf.py -p /dev/ttyUSB0 flash monitor  # flash + monitor in one
idf.py menuconfig                   # configure WiFi credentials and mDNS hostname
```

Requires ESP-IDF v6.0+ with `IDF_PATH` set and toolchain on `PATH`.  
Target: **ESP32-C6**. NimBLE stack (not Bluedroid). No unit tests exist.

## WiFi Credentials

Set via `idf.py menuconfig` → **FanESP Configuration**, or edit `sdkconfig` directly:
```
CONFIG_FANESP_WIFI_SSID="yourssid"
CONFIG_FANESP_WIFI_PASSWORD="yourpassword"
CONFIG_FANESP_MDNS_HOSTNAME="fanesp"
```
Never put credentials in `config.h` — those macros now alias the `CONFIG_` symbols.

## Architecture

The project is a BLE-to-WiFi bridge for FanLamp/LampSmart Pro ceiling fans. The ESP32 receives HTTP commands over WiFi and transmits them to the fan as BLE advertisements (no connection, pure broadcasting).

### Layer overview

```
HTTP client
    ↓ REST API (esp_http_server)
  API  [main/src/api.cpp]
    ↓ feature name + value string
  DeviceController  [main/src/device_controller.cpp]
    ↓ BleAdvEncCmd + BleAdvConfig
  Codec  [main/lib/fanesp/]
    ↓ raw advertisement bytes
  NimBLE  (ble_gap_adv_*)
    ↓ BLE advertisement
  Fan/light device
```

### `main/lib/fanesp/` — codec library

- **`Codec`** (abstract base in `ble_adv_codec.h`): two-phase pipeline.  
  *Decode*: `decrypt()` → prefix-check → `convert_to_enc()` → `BleAdvEncCmd` + `BleAdvConfig`  
  *Encode*: `convert_from_enc()` → prefix-prepend → `encrypt()` → `BleAdvAdvertisement`  
  Builder methods (`ble()`, `header()`, `prefix()`, `footer()`) configure each variant.

- **`FanLampEncoderV1`** / **`FanLampEncoderV2`** (in `fanlamp.h/cpp`): concrete codecs.  
  V1 uses LFSR-whiten + bit-reverse + CRC2 outer + CRC16 inner.  
  V2 uses XBOXES-whiten + optional AES-ECB signature + CRC16-CCITT.  
  `get_fanlamp_codecs()` returns all 12 configured static instances (FanLamp Pro v1/v2/v3/v3s1-s3, LampSmart Pro v1/v2/v3/vi1, R0/R1 remotes).

- **`BleAdvConfig`**: per-device session state. `id + index` is the stable device identity (not MAC). `device_id()` returns `"XXXXXXXX:N"` hex string used as the URL-safe identifier throughout the API.

- **`SupportedFeature` / `FeatureValue`**: codec capability descriptors. `get_supported_features()` returns named command presets (e.g. `"light"/"on"`, `"fan_speed"/"speed_3"`). `make_light_cw_cmd(cold, warm)` is virtual because V1 and V2 pack the cold/warm bytes into different arg positions.

### `DeviceController` — device registry + command dispatch

- Devices stored in NVS under namespace `"fanesp"` as blobs keyed `dev_0`, `dev_1`, …  
- `load_devices()` deduplicates by `conf` on load and rewrites NVS if any duplicates found.  
- `discover_device()` scans BLE passively, tries all 12 codecs on each advertisement, saves the first match, sets an event group bit to unblock the caller early.  
- `execute(device_id, feature, value)` is the generic dispatch path: looks up feature+value in `get_supported_features()` and calls `send_command()`. Use this for all named values.  
- `light_cw(device_id, cold, warm)` is the special-case path for parameterized brightness/CT (cmd `0x21`); bypasses the named-value lookup.

### `API` — REST over HTTP

All routes use wildcard matching (`httpd_uri_match_wildcard`). Device IDs in URLs are the `device_id()` hex strings, not MACs.

| Route | Handler |
|-------|---------|
| `GET /` | Serve embedded HTML UI |
| `GET /device` | List all device IDs as JSON array |
| `GET /device/{id}` | List supported features + named values for device |
| `GET /device/{id}/{feature}/{value}` | Execute named feature value |
| `GET /device/{id}/light_cw/{cold}-{warm}` | Set cold/warm brightness (0–255 each) |
| `GET /discover` | Run BLE scan, return found device ID |

The `_device_handler` dispatches to features vs. execute by counting `/` separators in the URI (1 = features, 3 = execute).

### `ha-ble-adv/`

Reference Python implementation (Home Assistant integration) by NicoIIT. Used as source-of-truth for protocol reverse engineering — command bytes, argument layouts, and codec configurations were ported from here. Not part of the ESP build.
