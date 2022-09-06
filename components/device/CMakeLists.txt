idf_build_get_property(project_dir PROJECT_DIR)

idf_component_register(SRCS "device.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES "esp_common" "json" "nvs_flash" "spiffs"
                       PRIV_REQUIRES "util")

EMBED_TXTFILES ${project_dir}/data/crypt_key