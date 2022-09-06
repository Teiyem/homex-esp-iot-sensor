#pragma once

#include <string.h>
#include <cJSON.h>
#include <chrono>
#include <time.h>
#include <algorithm>
#include <atomic>
#include "esp_err.h"
#include "esp_spiffs.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_sntp.h"
#include "mbedtls/cipher.h"
#include "mbedtls/base64.h"
#include "esp_system.h"
#include "util.h"

/** A singleton class that handles device-related tasks. */
class Device
{
    public:
        Device(Device &other)            = delete;
        void operator=(const Device &)    = delete;
        static Device *instance(void);

        void init(void);
        void restart(const uint16_t delay);
        void set_clock(void);
        void handle(void);

        esp_err_t read_info(char *obj, const char *mac);
        esp_err_t write_config(const device_config_t config);

        constexpr device_config_t *config(void){ return &_config;}
        
        bool configured(void);
        
        const char* now_to_str(void);

        /**
         * Get the current time as a time_point.
         * @return A time_point object.
         */
        std::chrono::_V2::system_clock::time_point now(void) noexcept 
        { 
            return std::chrono::system_clock::now(); 
        }

        esp_err_t encrypt(char *data, char **encrypted);
        esp_err_t decrypt(char *data, char **decrypted);

    private:
        Device(void) = default;

        static Device *_instance;
        
        const uint32_t  _clock_sync_time  = 300000; /* The amount of time the device will wait in milliseconds before attempting to sync the clock. */

        static constexpr const char *tag = "device";                           /* A constant used to identify the source of the log message of this class. */
        static constexpr const char *_config_path  = "/spiffs/config.json";    /* A pointer to the location of the config file. */
        static constexpr const char *_info_path  = "/spiffs/info.json";        /* A pointer to the location of the info file. */

        static device_config_t _config;

        static std::atomic_bool  _set_clock;
        static std::atomic_bool  _should_restart;
        static std::atomic_uint16_t _restart_delay;
        static size_t   _storage_available;
        static size_t   _storage_used;

        bool     _clock_set = false;                                /* Whether the clock has been set or not. */

        esp_err_t mount_storage(void);
        esp_err_t read_config(void);
        
        void write_to_storage(void);
        void config_sntp(void);
        void restart(void);

        static void on_time_sync(timeval *tv);
};