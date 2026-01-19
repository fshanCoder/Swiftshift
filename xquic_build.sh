#!/bin/bash
sudo apt-get install -y build-essential libevent-dev

cd xquic;
# cd quic-base                                                                                                    
# git checkout migration;

# get and build BoringSSL
git clone git@github.com:google/boringssl.git ./third_party/boringssl; cd ./third_party/boringssl
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make -j ssl crypto
cd ..
SSL_TYPE_STR="boringssl"
SSL_PATH_STR="${PWD}"
cd ../..

# build XQUIC with BoringSSL
# When build XQUIC with boringssl, by default XQUIC will use boringssl
# in third_party. If boringssl is deployed in other directories, SSL_PATH could be 
# used to specify the search path of boringssl
git submodule update --init --recursive
mkdir -p build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..

# exit if cmake error
if [ $? -ne 0 ]; then
    echo "cmake failed"
    exit 1
fi

make -j

cd tests/
keyfile=server.key
certfile=server.crt
openssl req -newkey rsa:2048 -x509 -nodes -keyout "$keyfile" -new -out "$certfile" -subj /CN=test.xquic.com