#pragma once

#include "esp_timer.h"
#include "esp_attr.h"

/** Network state enum */
typedef enum net_state_t {
	NOT_INITIALIZED, /* Indicates that the device's Wi-Fi has not been initialised. */
	INITIALIZED,	 /* Indicates that the device's Wi-Fi has been initialised. */
	CONNECTING,		 /* Indicates that the device is connecting to Wi-Fi. */
	WAITING_FOR_IP,	 /* Indicates that the device is awaiting an IP address from the router. */
	CONNECTED,		 /* Indicates that the device is connected to Wi-Fi. */
	DISCONNECTED	 /* Indicates that the device is not connected to Wi-Fi. */
} net_state_t;

/** Server state enum */
typedef enum server_state_t {
	UNKOWN,		/* Indicates that the server state is unknown. */
	REACHABLE,	/* Indicates that the server is reachable. */
	UNREACHABLE /* Indicates that the server is unavailable. */
} server_state_t;

typedef enum led_mode_t {
	STATIC,		/* Indicates that the LED will not blink. */
	SLOW_BLINK, /* Indicates that the LED will blink slowly. */
	FAST_BLINK	/* Indicates that the LED will be blinking rapidly. */
} led_mode_t;

/** Device configuration structure */
typedef struct device_config_t {
	char name[20];	   /* The device's friendly name. */
	char sta_ssid[20]; /* The router's ssid. */
	char sta_pass[20]; /* The router's password. */
	char host[20];	   /* The domain or ip of the server. */
	char uuid[20];	   /* The device's unique identifier. */
} device_config_t;

unsigned long IRAM_ATTR millis();