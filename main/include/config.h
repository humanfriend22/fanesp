#pragma once

// WiFi credentials (set via menuconfig → FanESP Configuration)
#define CFG_WIFI_SSID               CONFIG_FANESP_WIFI_SSID
#define CFG_WIFI_PASSWORD           CONFIG_FANESP_WIFI_PASSWORD

// BLE discovery
#define CFG_BLE_SCAN_DURATION_MS    15000
#define CFG_BLE_SCAN_ITVL           0x20    // 32 * 0.625ms = 20ms
#define CFG_BLE_SCAN_WINDOW         0x20    // 100% duty cycle

// BLE advertising (command transmit)
#define CFG_BLE_ADV_ITVL_MIN        0x20
#define CFG_BLE_ADV_ITVL_MAX        0x20
#define CFG_BLE_ADV_DURATION_MS     200
#define CFG_BLE_ADV_DELAY_MS        250

// WiFi
#define CFG_WIFI_MAX_RETRY          5
#define CFG_WIFI_CONNECT_TIMEOUT_MS 15000

// HTTP server
#define CFG_HTTP_MAX_SOCKETS        7
#define CFG_HTTP_MAX_URI_HANDLERS   8

// NVS
#define CFG_NVS_NAMESPACE           "fanesp"

// Discovery task
#define CFG_DISCOVERY_TASK_STACK    4096
#define CFG_DISCOVERY_TASK_PRIORITY 5
