package main

import (
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	pb "gopkg.in/cheggaaa/pb.v1"
)

//var mutex = &sync.Mutex{}
var wg sync.WaitGroup

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU()) // Run faster & more resource !
	banner()

	fileName := flag.String("f", "", "Azorult request file")
	threats := flag.Int("t", 10, "Number of threats")
	dump := flag.Bool("d", false, "Dump the request content once decrypted")
	flag.Parse()

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	rawFile, err := ioutil.ReadFile(*fileName)
	if err != nil {
		log.Fatalf("Error while opening file: %s", err)
	}

	file := []byte{}

	if len(rawFile) > 3000 {
		file = rawFile[:3000]
	} else {
		file = rawFile
	}

	print("First trying default key...", "*")
	data := xor(file, []byte{0x03, 0x55, 0xae})
	if check(string(data)) {
		print("Key Found !", "+")
		print(xxd([]byte{0x03, 0x55, 0xae}), "+")
		if *dump {
			fmt.Println("\n\n" + string(data))
		}
		os.Exit(0)
	}

	print("Generating keyspace: ", "**")
	s := spinner.New(spinner.CharSets[35], 100*time.Millisecond) // Build our new spinner
	s.Start()

	channel := make(chan uint32, 16581375)
	for i := 0; i < 16581375; i++ {
		channel <- uint32(i)
	}
	s.Stop()
	fmt.Println("OK")
	close(channel)

	fmt.Println("")
	progressBar := pb.New(16581375)
	progressBar.SetWidth(80)
	progressBar.Start()

	for i := 0; i < *threats; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range channel {
				k := make([]byte, 4)
				binary.BigEndian.PutUint32(k, uint32(key))
				//print(xxd(k[1:]), "*")
				data := xor(file, k[1:])
				if check(string(data)) {
					progressBar.Finish()
					fmt.Println("")
					print("Key Found !", "+")
					print(xxd(k[1:])+"\n", "+")
					if *dump {
						fmt.Println("\n\n" + string(data))
					}
					os.Exit(0)
				}
				progressBar.Increment()

			}

		}()
	}
	wg.Wait()
	progressBar.Finish()
	fmt.Println("")
	print("End of keyspace :( ", "-")

}

func check(data string) bool {
	knownStrings := []string{"353E77DF-928B-4941-A631-512662F0785A3061-4E40-BBC2-3A27F641D32B-54FF-44D7-85F3-D950F519F12F", "DV8CF101-053A-4498-98VA-EAB3719A088W-VF9A8B7AD-0FA0-4899-B4RD-D8006738DQCD", "Windows", "Microsoft", "System", "MachineID", "Computer"}

	for _, j := range knownStrings {
		if strings.Contains(string(data), j) {
			return true
		}
	}
	return false
}

func print(str string, status string) {

	red := color.New(color.FgRed).Add(color.Bold)
	yellow := color.New(color.FgYellow).Add(color.Bold)
	green := color.New(color.FgGreen).Add(color.Bold)

	if status == "*" {
		yellow.Print("[*] ")
		fmt.Println(str)
	} else if status == "+" {
		green.Print("[+] ")
		fmt.Println(str)
	} else if status == "-" {
		red.Print("[-] ")
		fmt.Println(str)
	} else if status == "!" {
		red.Print("[!] ")
		fmt.Println(str)
	} else if status == "**" {
		yellow.Print("[*] ")
		fmt.Print(str)
	}
}

func xxd(data []byte) string {
	out := ""
	for i, j := range data {
		out += fmt.Sprintf("0x%02X", j)
		if i != len(data)-1 {
			out += ", "
		}
		if i+1%12 == 0 {
			out += "\n"
		}
	}
	return out
}

func xor(data []byte, key []byte) []byte {
	out := []byte{}
	for i := 0; i < len(data); i++ {
		out = append(out, (data[i] ^ (key[(i % len(key))])))
	}
	return out
}

func banner() {
	red := color.New(color.FgRed).Add(color.Bold)
	blue := color.New(color.FgBlue).Add(color.Bold)
	green := color.New(color.FgGreen).Add(color.Bold)
	banner, _ := base64.StdEncoding.DecodeString("CiAgICAgX19fXyAgX19fXyAgX19fXyAgXyAgX18KICAgIC8gIF8gXC9fICAgXC8gIF8gXC8gfC8gLwogICAgfCAvIFx8IC8gICAvfCAvIFx8fCAgIC8gCiAgICB8IHwtfHwvICAgL198IFxfL3x8ICAgXCAKICAgIFxfLyBcfFxfX19fL1xfX19fL1xffFxfXAo9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAgICAgICAgICAgICAgICAgICAgICAgIAoK")
	red.Print(string(banner))
	blue.Print("# Author: ")
	green.Println("Ege Balcı")
	fmt.Println("") // Line feed
}
