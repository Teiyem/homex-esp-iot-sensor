#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <driver/gpio.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sensor type
 */
typedef enum
{
    DHT_TYPE_DHT11 = 0, //!< DHT11
    DHT_TYPE_DHT22,     //!< DHT22
    DHT_TYPE_SI7021     //!< Itead SI7021
} dht_sensor_type_t;


esp_err_t dht_init(gpio_num_t pin, bool pull_up);

esp_err_t dht_read_data(dht_sensor_type_t sensor_type, gpio_num_t pin, int16_t *humidity, int16_t *temperature);

esp_err_t dht_read_float_data(dht_sensor_type_t sensor_type, gpio_num_t pin, float *humidity, float *temperature);

#ifdef __cplusplus
}
#endif
