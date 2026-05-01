idf_component_register(
    SRCS        "src/provisioner.c"
                "src/provisioner_proto.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES    esp_driver_uart vfs
    PRIV_REQUIRES mbedtls log esp_common esp_timer
)
