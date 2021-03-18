- cmake VERSION 3.10 +
- libpcap libpcap-devel  centos: yum install libpcap && yum install libpcap-devel
> Change line in CMakeLists.txt file /usr/local/lib/libpcap.so to your libpcap path


#### TODO LIST
- [ ] tcpdump pcap file parse support
  - [ ] ethernet frame
  - protocol
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
# debug
make build
# release
# will enable 01 optimization
make release
```