package main

import (
    "log"
    "os"
    "os/signal"
    "time"
	"net"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf"
)


//disini kita akan lakukan
//- remote Memlock untuk kernel dibawah <5.11
//- load object dari protocol_coub.go
//- menentukan interface mana yg akan kita attach xdp programmnya
//- bagaimana cara untuk print result ebfp map 'BPF_MAP_TYPE_ARRAY'
//	- kita aksess dahulu map objectnya -> *ebpf.Map
//	- kita iterate map dengan dengan Iterate() function cillium
//	  - untuk mendapat key & value 
//- print ebpf map 
func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    var objs packetProtocolObjects //dicari pada file 'packetprotocol_bpfel.go' 
    if err := loadPacketProtocolObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF object:", err)
    }
    defer objs.Close()

    ifname := "wlp3s0"
    iface, err := net.InterfaceByName(ifname)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach count_packets to the network interface.
    link, err := link.AttachXDP(link.XDPOptions{ 
        Program:   objs.GetPacketProtocol,	//program yg kita load di interface
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatal("Attaching XDP:", err)
    }
    defer link.Close()

    log.Printf("Analysing packets on %s..", ifname)

    tick := time.Tick(time.Second)
    //kita buat channel, untuk select case for loop
    stop := make(chan os.Signal, 5)
    signal.Notify(stop, os.Interrupt)

    for {
        select {
            case <-tick:
		//kita call function & ambil map dari object.Protcool count
                printMap(objs.ProtocolCount)
		
		if err != nil {
                   log.Fatal("Map lookup:", err)
	        }
	    case <-stop:
		log.Print("Received signal, exiting..")
                return
	}

    }
}
//
func printMap(bpfMap *ebpf.Map) {
    //define vairaoble sesuai map type
    var key uint32
    var value uint64
    
    //kita perlu iterate ufnction dari 'cillium'
    iterator := bpfMap.Iterate()
    //untuk print kita for loop  sesui example dari 'cillium'
    for iterator.Next(&key, &value) {
        //check jika value tidak 0, karena jika kosong artinya map juga kosong
	if value != 0 && key != 0 {
            log.Printf("Key: %d, Protocol Name: %s Value: %d\n", key, value)
	}
    }
    if err := iterator.Err(); err != nil {
        log.Fatalf("Error during map iteration: %v", err)
    }
}
