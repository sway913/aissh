package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/fatedier/frp/aissh"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	home, e := os.UserConfigDir()
	if e != nil {
		log.Fatal(e)
	}
	o := aissh.AgentOptions{}
	flag.StringVar(&o.Host, "server", aissh.DefaultHost, "TLS tunnel server hostname")
	flag.StringVar(&o.APIURL, "api-url", aissh.DefaultAPIURL, "HTTPS registration URL")
	flag.IntVar(&o.TunnelPort, "tunnel-port", aissh.DefaultTunnelPort, "TLS tunnel port")
	flag.IntVar(&o.SSHPort, "ssh-port", 22, "local SSH service port")
	flag.StringVar(&o.CAFile, "ca", "", "custom tunnel CA certificate; default uses bundled trust root")
	flag.StringVar(&o.StateDir, "state-dir", filepath.Join(home, "aissh"), "local runtime directory (no device private key)")
	showVersion := flag.Bool("version", false, "print aissh version and commit")
	flag.Parse()
	if *showVersion {
		fmt.Println(aissh.VersionString())
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := aissh.RunAgent(ctx, o); e != nil {
		log.Fatal(e)
	}
}
