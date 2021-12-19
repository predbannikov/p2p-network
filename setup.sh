#! /bin/bash
cd ~
mkdir boost
cd boost
wget https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.gz
tar -xzf boost_1_78_0.tar.gz
cd boost_1_78_0/
./bootstrap.sh
sudo ./b2 install --prefix=/usr


