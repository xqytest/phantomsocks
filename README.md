# phantomsocks
A proxy server for Linux/Windows/macOS with Pcap/RawSocket/WinDivert to modify packets

这是thphd的修改增强版。详情见 <https://2047.name/t/16729>


## Usage
```
phantomsocks
  -c string
    	Config (default "default.conf")
  -device string
    	Device
  -dns string
    	DNS
  -hosts string
    	Hosts
  -log int
    	LogLevel
  -pac string
    	PACServer
  -sni string
    	SNIProxy
  -socks string
    	Socks proxy
  -redir string
      Netfilter TCP redirect
  -proxy string
      Set system proxy
```
### Socks5:
```
Linux(pcap&rawsocket):
sudo ./phantomsocks -device eth0 -socks 0.0.0.0:1080

Windows(windivert):
phantomsocks -socks 0.0.0.0:1080

macOS:
./phantomsocks -device en0 -socks 127.0.0.1:1080 -proxy socks://127.0.0.1:1080
```
### Redirect:
```
Linux(pcap&rawsocket):
iptables -t nat -A OUTPUT -d 6.0.0.0/8 -p tcp -j REDIRECT --to-port 6
./phantomsocks -device eth0 -dns :53 -redir :6

Windows(windivert):
./phantomsocks -redir 0.0.0.0:6 -proxy redirect://0.0.0.0:6
```

## Configure
```
  server=*          #domains below will use this DNS or proxy server
  ttl=*             #the fake tcp packet will use this TTL
  domain=ip,ip,...  #this domain will use these IPs
  domain            #this domain will be resolved by DNS
  ip:port           #this ip:port will send fake packet when creating connection
  method=*          #the methods to modify TCP
```
### server:
```
  server=udp://8.8.8.8:53
  server=tcp://8.8.8.8:53
  server=tls://8.8.8.8:853
  server=tfo://8.8.8.8:53 #Linux
  
  server=udp://8.8.8.8:53/ecs=35.190.247.1
  server=http://hostname:port                     #http proxy server
  server=socks://hostname:port                    #socks5 proxy server
  server=ss://method:password@hostname:port       #Shadowsocks proxy server
```
### methods:
```
  none              #no modification
  ttl               #the fake tcp packets will use the TTL you set
  w-md5             #the fake tcp packets will have a wrong md5 option
  w-csum            #the fake tcp packets will have a wrong checksum
  w-ack             #the fake tcp packets will have a wrong ACK number
  w-seq             #the fake tcp packets will have a wrong SEQ number
  w-time            #the fake tcp packets will have a wrong timestamp
  s-seg             #the first tcp payload will be very small
  tfo               #SYN packet will take a part of data when the server supports TCP Fast Open
  https             #domains below will be move to https when using http on port 80
  df                #the true tcp packets will not be fragmented
  ipv4              #domains below will only connect via ipv4
  ipv6              #domains below will only connect via ipv6
  proxy             #domains below will connect via above proxy server
```
## Installation
go get github.com/macronut/phantomsocks

## Compile
cd $GOPATH/src/github.com/macronut/phantomsocks/

go build

### pcap version
static linking for pcap
```
sudo apt-get install -y libpcap-dev
go build -ldflags '-extldflags "-static"'
```
### raw socket version
raw socket is Linux only
```
go build -tags rawsocket
```
### windivert version
windivert is Windows only
```
env GOOS=windows GOARCH=amd64 go build -tags windivert
```

### cross & static compile pcap version on Ubuntu 18.04
Install dependencies
```
apt-get install git autoconf automake bison build-essential flex gawk gettext gperf libtool pkg-config libpcap-dev
```
Download & uncompress tool-chain
```
cd ~/Downloads
wget https://downloads.openwrt.org/releases/19.07.2/targets/ramips/mt7621/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64.tar.xz
tar -xJvf openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64.tar.xz
```
Set environment variable
```
export PATH=$PATH:~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl/bin: && export STAGING_DIR=~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl
```
Download & uncompress libpcap
```
wget https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz
tar -xzvf libpcap-1.9.1.tar.gz
```
Build libpcap
```
cd libpcap-1.9.1
./configure --host=mipsel-openwrt-linux-musl --prefix='~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl'
make && make install 
```
Build phantomsocks
```
cd ~/go/src/github.com/Macronut/phantomsocks
env GOOS=linux GOARCH=mipsle CGO_ENABLED=1 CC='~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl/bin/mipsel-openwrt-linux-gcc'  go build  -ldflags '-extldflags "-static"'
```
