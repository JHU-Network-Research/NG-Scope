FROM ubuntu:24.04

RUN apt update && apt install -y cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev libuhd-dev uhd-host gnuradio
