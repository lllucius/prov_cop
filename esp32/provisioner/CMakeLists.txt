idf_component_register(
    SRCS        "src/provisioner.c"
    INCLUDE_DIRS "include"
    REQUIRES    esp_driver_uart vfs
    PRIV_REQUIRES mbedtls log esp_common
)
