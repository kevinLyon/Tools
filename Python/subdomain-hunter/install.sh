#!/bin/bash

apt-get update
apt-get install lolcat -y #Dependency
apt-get install figlet -y #Dependency
cp Bloody.flf /usr/share/figlet #Banner
pip3 install dnspython
echo "DONE :)"
