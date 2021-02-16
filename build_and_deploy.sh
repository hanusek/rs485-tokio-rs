#!/bin/sh

cross build --target=arm-unknown-linux-gnueabihf
sshpass -p "temppwd" scp ./target/arm-unknown-linux-gnueabihf/debug/rs485 debian@bbb:/home/debian