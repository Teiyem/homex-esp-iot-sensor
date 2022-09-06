#pragma once

#include <cJSON.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_smartconfig.h"
#include "smartconfig_ack.h"
#include "freertos/FreeRTOS.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "device.h"
#include "sensor.h"
#include "led.h"
#include "util.h"

/** A singleton class that handles network-related tasks. */
class Network
{   
    public:
        Network(Network &other)            = delete;
        void operator=(const Network &)    = delete;
        static Network *instance(void);

        void init(Led *led);
        void handle(void);

    private:
        Network() = default;
        static Network *_instance;
        static Device *_device;
        static Sensor *_sensor;
        static Led *_led;

        static std::atomic_bool _reconnect;
        static std::atomic_bool _get_key;
        static std::atomic_bool _got_key;

        static char _mac[13];
        static char _api_key[33];

        static uint8_t _retries;

        static httpd_handle_t _server;
        static esp_http_client_config_t _client_config;
        static esp_http_client_handle_t _client;
        static net_state_t _net_state;
        static server_state_t _server_state;

        static constexpr const char *tag = "network";                   /* A constant used to identify the source of the log message of this class. */
        static constexpr const char *x_key = "aesY}zeN]v4DOp@o2)-";     /* A Key used to verify the device's identity with the server. */
        static constexpr const char *app_json = "application/json";     /* Json content-type header value. */
        static constexpr int8_t _strlen = -1;                           /* Tells httpd_resp_send to use strlen() on the buffer to get the buffer's length. */        

        const uint8_t _max_retries = 10;                                /* The maximum number of times the device will attempt to connect to Wi-Fi before giving up. */
        const uint32_t _ping_interval = 300000;                         /* The amount of time the device will wait before attempting to ping the server. */
        const uint32_t _sensor_sync = 360000;                           /* The amount of time the device will wait before attempting to send sensor data to the server. */
        uint16_t connect_interval = 1000;                               /* The amount of time the device will wait before attempting to reconnect to Wi-Fi. */
        uint32_t _last_sync = 0;                                        /* The last time the temp and humidity data was posted to the server. */
        uint32_t _last_ping = 0;                                        /* The last time a ping was sent to the server. */

        static void wifi_evt_handler(void *arg, esp_event_base_t event_base, const int32_t event_id, void *event_data);
        static void sc_evt_handler(void *arg, const esp_event_base_t event_base, int32_t event_id, void *event_data);

        static esp_err_t on_error(httpd_req_t *req, const char *status = "500");
        static esp_err_t auth(httpd_req_t *req);
        static esp_err_t on_get_config(httpd_req_t *req);
        static esp_err_t on_post_config(httpd_req_t *req);
        static esp_err_t on_info(httpd_req_t *req);
        static esp_err_t on_sensor(httpd_req_t *req);
        static esp_err_t on_restart(httpd_req_t *req);
        static esp_err_t on_update(httpd_req_t *req);
        static esp_err_t on_setup(smartconfig_event_got_ssid_pswd_t *data);

        static void smart_config(void);
        static void configure_client_config(void);
        static void configure_ota(httpd_req_t *req);

        esp_err_t send_req(const char *path, const char *body, const esp_http_client_method_t method);
        esp_err_t get_mac(void);

        void on_send(void);
        void configure_wifi(void);
        void configure_server(void);
        void reconnect_wifi(void);
        void on_update_state(void);
        void get_key(void);
};