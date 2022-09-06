#pragma once

#include "esp_err.h"
#include "esp_log.h"
#include "util.h"
#include "driver/gpio.h"
#include "dht.h"

/* A class that handles sensor-related tasks. */
class Sensor
{
   public:
      explicit constexpr Sensor(const gpio_num_t gpio_num) : _dht_pin{gpio_num} {}
      esp_err_t init();
      esp_err_t read(int16_t *temp, int16_t *humidity);

   private:
      const gpio_num_t _dht_pin; /** The pin number that the dht sensor is connected to. */
      static constexpr const char *tag = "sensor"; /* A constant used to identify the source of the log message of this class. */

};