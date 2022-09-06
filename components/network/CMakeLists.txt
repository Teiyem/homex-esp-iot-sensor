idf_build_get_property(project_dir PROJECT_DIR)

idf_component_register(SRCS "network.cpp"
        INCLUDE_DIRS "include"
        REQUIRES "freertos" "esp_netif" "esp_event" "lwip" "esp_wifi" "esp_common" "esp_http_server" "json" "esp_http_client"
        PRIV_REQUIRES "device" "sensor" "util" "led"
        EMBED_TXTFILES ${project_dir}/keys/sc_key)
