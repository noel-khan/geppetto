cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(tinyusb_test C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

# Define project source executable
add_executable(tinyusb_test main.cpp)

# --- FIX: Generate the PIO compilation header block automatically ---
pico_generate_pio_header(tinyusb_test ${CMAKE_CURRENT_LIST_DIR}/ws2812.pio)

# CRITICAL: Include the current folder so TinyUSB can find your tusb_config.h file
target_include_directories(tinyusb_test 
    PRIVATE ${CMAKE_CURRENT_LIST_DIR}
    /home/user/.pico-sdk/sdk/2.2.0/src/host/pico_rand/include
)

# --- FIX: Link hardware_pio alongside standard runtime layers ---
target_link_libraries(tinyusb_test 
    pico_stdlib 
    tinyusb_device
    # blinky light
    hardware_pio
    # MSC support
    hardware_flash
    hardware_sync
    pico_rand
)

pico_add_extra_outputs(tinyusb_test)
