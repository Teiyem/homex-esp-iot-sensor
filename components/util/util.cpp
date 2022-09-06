#include "util.h"

/** Milliseconds since the ESP6266 was booted. */
unsigned long IRAM_ATTR millis()
{
  return (unsigned long) (esp_timer_get_time() / 1000ULL);
}