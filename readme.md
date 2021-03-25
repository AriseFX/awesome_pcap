#### dependence
- cmake VERSION 3.10 +
- libpcap libpcap-devel  centos: yum install libpcap && yum install libpcap-devel
- cJSON v1.7.14
- rax https://github.com/antirez/rax

#### TODO LIST
- [ ] tcpdump pcap file parse support
  - [x] ethernet frame
  - protocol
    - [x] ipv4
    - [x] ipv6
      - [x] tcp
        - [ ] http
        - [ ] mqtt
        - [ ] RESP (redis protocol)
        - [ ] mysql protocol
        - [ ] dns
      - [x] udp
        - [ ] dns
- [ ] GUI support 
  - gtk
- Resource limit
  - [ ] cpu limit
  - [ ] rate limit
  - [x] memory limit

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