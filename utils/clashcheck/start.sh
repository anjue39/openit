#!/bin/sh
#python 3.x
#pwd /home/$USER/clashcheck
#with log ↓          #no log ↓ 
#nohup ./start.sh &  #nohup ./start.sh > /dev/null 2>&1 &
#TODO start clashcheck with while
#macOS -> `zsh: command not found: timeout` -> https://stackoverflow.com/questions/3504945/timeout-command-on-mac-os-x

nginx
while true; do timeout -k 20 4m python main.py; done
