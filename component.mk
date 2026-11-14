COMPONENT_SRCDIRS = \
	src \
	src/crypto/refc
COMPONENT_ADD_INCLUDEDIRS = \
	include
COMPONENT_PRIV_INCLUDEDIRS = \
	src

COMPONENT_DEPENDS = lwip mbedtls

ifndef CONFIG_WIREGUARD_SERVER
COMPONENT_OBJEXCLUDE += src/esp_wireguard_server.o
endif
