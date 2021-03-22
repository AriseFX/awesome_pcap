#### dependence
- cmake VERSION 3.10 +
- libpcap libpcap-devel  centos: yum install libpcap && yum install libpcap-devel
- cJSON v1.7.14


#### TODO LIST
- [ ] tcpdump pcap file parse support
  - [x] ethernet frame
  - protocol
    - [x] ipv4
    - [x] ipv6
      - [ ] tcp
        - [ ] http
        - [ ] mqtt
        - [ ] RESP (redis protocol)
        - [ ] mysql protocol
      - [ ] udp
- [ ] GUI support 
  - gtk
- Resource limit
  - [ ] cpu limit
  - [ ] rate limit
  - [ ] memory limit

#### build
```shell
# install dependence
make deps
# debug
make build
# release
# will enable 01 optimization
make release
# clean
make clean
```