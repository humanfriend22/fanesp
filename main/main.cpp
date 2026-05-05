#include "sdkconfig.h"
#include "include/device_controller.h"
#include "include/api.h"
#include "include/config.h"

#include <esp_log.h>
#include <esp_netif.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <host/ble_gap.h>
#include <host/ble_hs.h>
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>
#include <nvs_flash.h>
#include "mdns.h"

static const char *TAG = "fanesp";

static DeviceController g_controller;
static API *g_api = nullptr;

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
static EventGroupHandle_t s_wifi_event_group;
static int s_retry_count = 0;
#define WIFI_MAX_RETRY CFG_WIFI_MAX_RETRY

// ─── BLE ────────────────────────────────────────────────────────────────────

static void discovery_task(void * /*arg*/) {
    ESP_LOGI(TAG, "Discovery task started, scanning...");
    auto device = g_controller.discover_device(CFG_BLE_SCAN_DURATION_MS);
    if (device.has_value()) {
        ESP_LOGI(TAG, "Device discovered: mac=%s codec_id=0x%02X", device->mac_str().c_str(),
                 device->codec_id);
        g_controller.light(0, false);
    } else {
        ESP_LOGW(TAG, "No device discovered");
    }
    vTaskDelete(nullptr);
}

static void on_ble_sync() {
    auto devices = g_controller.load_devices();
    if (!devices.empty()) {
        ESP_LOGI(TAG, "Loaded %zu devices from NVS", devices.size());
    } else {
        xTaskCreate(discovery_task, "discovery", CFG_DISCOVERY_TASK_STACK, nullptr,
                    CFG_DISCOVERY_TASK_PRIORITY, nullptr);
    }
}

static void on_ble_reset(int reason) {
    ESP_LOGW(TAG, "BLE host reset: reason=%d", reason);
}

static void nimble_host_task(void * /*arg*/) {
    ESP_LOGI(TAG, "NimBLE host task started");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

// ─── WiFi ───────────────────────────────────────────────────────────────────

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id,
                               void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_retry_count++;
        ESP_LOGI(TAG, "WiFi disconnected, reconnecting... (attempt %d)", s_retry_count);
        esp_wifi_connect();
        // Signal failure only during initial connect (wifi_init_sta waiting on event group)
        if (s_retry_count >= WIFI_MAX_RETRY) {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_count = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta() {
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler, nullptr,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler, nullptr,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {};
    strncpy((char *)wifi_config.sta.ssid, CFG_WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, CFG_WIFI_PASSWORD,
            sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to WiFi SSID: %s", CFG_WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(CFG_WIFI_CONNECT_TIMEOUT_MS));

    if (!(bits & WIFI_CONNECTED_BIT)) {
        ESP_LOGW(TAG, "WiFi not connected yet, will keep retrying in background");
    }
}

// ─── mDNS ───────────────────────────────────────────────────────────────────

static void initialise_mdns() {
    mdns_init();
    mdns_hostname_set(CONFIG_FANESP_MDNS_HOSTNAME);
    mdns_instance_name_set("FanESP Controller");

    mdns_txt_item_t txt[] = {{"path", "/"}};
    ESP_ERROR_CHECK(mdns_service_add("FanESP", "_http", "_tcp", 80, txt, 1));

    ESP_LOGI(TAG, "mDNS: http://%s.local", CONFIG_FANESP_MDNS_HOSTNAME);
}

// ─── app_main ───────────────────────────────────────────────────────────────

extern "C" void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    wifi_init_sta();
    initialise_mdns();
    g_api = new API(&g_controller);
    g_api->start();

    err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %d", err);
        return;
    }

    ble_hs_cfg.sync_cb = on_ble_sync;
    ble_hs_cfg.reset_cb = on_ble_reset;

    nimble_port_freertos_init(nimble_host_task);
}
