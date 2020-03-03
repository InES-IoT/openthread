#!/bin/sh
# Shell script to quickly setup nodes for openthread stack testing

TTY_SERVERDEVICE='/dev/ttyACM0'
TTY_CLIENTDEVICE='/dev/ttyUSB0'

connect_to_thread_network()
{
    TTY=$1
    
    python3 .tests/test_cli_cmd.py 'ifconfig up' 'Done' $TTY
    python3 .tests/test_cli_cmd.py 'thread start' 'Done' $TTY
    python3 .tests/test_cli_cmd.py 'coap start' 'Done' $TTY
    python3 .tests/test_cli_cmd.py 'coap resource test-resource' 'Done' $TTY
}

# 1. step: setup nRFDevKit
python3 .tests/test_cli_cmd.py 'channel 12' 'Done' $TTY_SERVERDEVICE
python3 .tests/test_cli_cmd.py 'masterkey 6dca69dfe02e7d1ec44269ee1679e6e0' 'Done' $TTY_SERVERDEVICE
python3 .tests/test_cli_cmd.py 'panid 0xb3c1' 'Done' $TTY_SERVERDEVICE

# 2. step: connect both devices to thread network
connect_to_thread_network $TTY_SERVERDEVICE
connect_to_thread_network $TTY_CLIENTDEVICE


