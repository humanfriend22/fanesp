#include "include/api.h"
#include "include/config.h"
#include "fanlamp.h"
#include "index_html.h"
#include <esp_log.h>
#include <cstring>
#include <cstdio>

static const char *TAG = "fanesp_api";
static API *api = nullptr;

API::API(DeviceController *controller)
    : _controller(controller), _server(nullptr) {
    api = this;
}

API::~API() {
    stop();
}

esp_err_t API::start() {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = CFG_HTTP_MAX_SOCKETS;
    config.max_uri_handlers = CFG_HTTP_MAX_URI_HANDLERS;
    config.uri_match_fn = httpd_uri_match_wildcard;

    esp_err_t err = httpd_start(&_server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %d", err);
        return err;
    }

    // GET / - serve HTML
    httpd_uri_t root = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = _root_handler,
        .user_ctx = nullptr,
    };
    httpd_register_uri_handler(_server, &root);

    // GET /device - list MACs
    httpd_uri_t get_device_list = {
        .uri = "/device",
        .method = HTTP_GET,
        .handler = _get_device_list_handler,
        .user_ctx = nullptr,
    };
    httpd_register_uri_handler(_server, &get_device_list);

    // GET /device/* - get features OR execute (routed by segment count)
    httpd_uri_t get_device = {
        .uri = "/device/*",
        .method = HTTP_GET,
        .handler = _device_handler,
        .user_ctx = nullptr,
    };
    httpd_register_uri_handler(_server, &get_device);

    // GET /discover - start discovery
    httpd_uri_t get_discover = {
        .uri = "/discover",
        .method = HTTP_GET,
        .handler = _discover_handler,
        .user_ctx = nullptr,
    };
    httpd_register_uri_handler(_server, &get_discover);

    ESP_LOGI(TAG, "REST API server started");
    return ESP_OK;
}

void API::stop() {
    if (_server) {
        httpd_stop(_server);
        _server = nullptr;
        ESP_LOGI(TAG, "REST API server stopped");
    }
}

esp_err_t API::_get_device_list_handler(httpd_req_t *req) {
    if (!api) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    const auto &devices = api->_controller->get_devices();
    char response[512] = {0};
    int pos = snprintf(response, sizeof(response), "[");

    for (size_t i = 0; i < devices.size() && pos < (int)sizeof(response) - 30; i++) {
        pos += snprintf(response + pos, sizeof(response) - pos, "%s\"%s\"", i > 0 ? "," : "",
                        devices[i].conf.device_id().c_str());
    }

    snprintf(response + pos, sizeof(response) - pos, "]");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t API::_device_handler(httpd_req_t *req) {
    // Count slashes after /device/ to decide: 1 segment = features, 3 segments = execute
    const char *after = req->uri + 7; // skip "/device"
    int slashes = 0;
    for (const char *p = after; *p; p++) {
        if (*p == '/') slashes++;
    }
    if (slashes == 1) {
        return _get_device_features_handler(req);
    } else if (slashes == 3) {
        return _execute_feature_handler(req);
    }
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_sendstr(req, "{\"error\":\"invalid path\"}");
    return ESP_FAIL;
}

esp_err_t API::_get_device_features_handler(httpd_req_t *req) {
    if (!api) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // Extract device_id from URI: /device/{id}
    const char *uri = req->uri;
    char dev_id[13] = {0};
    sscanf(uri, "/device/%11[^/]", dev_id);

    const auto &devices = api->_controller->get_devices();
    int device_idx = -1;
    for (size_t i = 0; i < devices.size(); i++) {
        if (strcmp(devices[i].conf.device_id().c_str(), dev_id) == 0) {
            device_idx = i;
            break;
        }
    }

    if (device_idx < 0) {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_sendstr(req, "{\"error\":\"not found\"}");
        return ESP_OK;
    }

    // Get features for codec
    auto fanlamp_codecs = fanesp::codecs::get_fanlamp_codecs();
    fanesp::Codec *codec = nullptr;
    for (size_t i = 0; i < fanlamp_codecs.size(); i++) {
        if (fanlamp_codecs[i]->get_codec_id() == devices[device_idx].codec_id) {
            codec = fanlamp_codecs[i];
            break;
        }
    }

    if (!codec) {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_sendstr(req, "{\"error\":\"not found\"}");
        return ESP_OK;
    }

    auto features = codec->get_supported_features();
    char response[1024] = {0};
    int pos = snprintf(response, sizeof(response), "{\"features\":[");

    for (size_t i = 0; i < features.size() && pos < (int)sizeof(response) - 100; i++) {
        pos += snprintf(response + pos, sizeof(response) - pos,
                        "%s{\"name\":\"%s\",\"values\":[", i > 0 ? "," : "",
                        features[i].feature_name.c_str());

        for (size_t j = 0; j < features[i].values.size() && pos < (int)sizeof(response) - 50;
             j++) {
            pos += snprintf(response + pos, sizeof(response) - pos, "%s\"%s\"",
                            j > 0 ? "," : "", features[i].values[j].name.c_str());
        }

        pos += snprintf(response + pos, sizeof(response) - pos, "]}");
    }

    snprintf(response + pos, sizeof(response) - pos, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t API::_discover_handler(httpd_req_t *req) {
    if (!api) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    auto device = api->_controller->discover_device(CFG_BLE_SCAN_DURATION_MS);
    char response[256] = {0};

    if (device.has_value()) {
        snprintf(response, sizeof(response), "{\"status\":\"found\",\"id\":\"%s\"}",
                 device->conf.device_id().c_str());
    } else {
        snprintf(response, sizeof(response), "{\"status\":\"not_found\"}");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t API::_execute_feature_handler(httpd_req_t *req) {
    if (!api) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // Extract from URI: /device/{id}/{feature}/{value}
    const char *uri = req->uri;
    char dev_id[13] = {0};
    char feature[32] = {0};
    char value[32] = {0};

    if (sscanf(uri, "/device/%11[^/]/%31[^/]/%31s", dev_id, feature, value) != 3) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"error\":\"invalid request\"}");
        return ESP_FAIL;
    }

    const auto &devices = api->_controller->get_devices();
    int device_idx = -1;
    for (size_t i = 0; i < devices.size(); i++) {
        if (strcmp(devices[i].conf.device_id().c_str(), dev_id) == 0) {
            device_idx = i;
            break;
        }
    }

    if (device_idx < 0) {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_sendstr(req, "{\"error\":\"not found\"}");
        return ESP_OK;
    }

    bool success = false;
    if (strcmp(feature, "light_cw") == 0) {
        int cold = 0, warm = 0;
        if (sscanf(value, "%d-%d", &cold, &warm) != 2) {
            httpd_resp_set_status(req, "400 Bad Request");
            httpd_resp_sendstr(req, "{\"error\":\"light_cw requires {cold}-{warm} (0-255 each)\"}");
            return ESP_FAIL;
        }
        success = api->_controller->light_cw(device_idx, cold, warm);
    } else {
        success = api->_controller->execute(device_idx, feature, value);
    }

    const char *response = success ? "{\"status\":\"ok\"}" : "{\"status\":\"error\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t API::_root_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, INDEX_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}
