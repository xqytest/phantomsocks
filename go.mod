module github.com/macronut/phantomsocks

go 1.18

require (
	github.com/chai2010/winsvc v0.0.0-20200705094454-db7ec320025c
	github.com/google/gopacket v1.1.19
	github.com/macronut/go-tproxy v0.0.0-20190726054950-ef7efd7f24ed
	github.com/macronut/godivert v0.0.0-20220121081532-78e5dd672daf
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a
	golang.zx2c4.com/wireguard v0.0.0-20220316235147-5aff28b14c24
	golang.zx2c4.com/wireguard/tun/netstack v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/btree v1.0.1 // indirect
	github.com/williamfhe/godivert v0.0.0-20181229124620-a48c5b872c73 // indirect
	golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
	gvisor.dev/gvisor v0.0.0-20211020211948-f76a604701b6 // indirect
)

replace (
	golang.zx2c4.com/wireguard => github.com/macronut/wireguard-go v0.0.0-20220521185917-e58dbe0aec0c
	golang.zx2c4.com/wireguard/tun => github.com/macronut/wireguard-go/tun v0.0.0-20220521185917-e58dbe0aec0c
	golang.zx2c4.com/wireguard/tun/netstack => github.com/macronut/wireguard-go/tun/netstack v0.0.0-20220521185917-e58dbe0aec0c
)
