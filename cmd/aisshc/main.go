package main

import (
	"context"
	"flag"
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
	flag.StringVar(&o.Host, "server", aissh.DefaultHost, "aissh server IP or hostname")
	flag.IntVar(&o.APIPort, "api-port", aissh.DefaultAPIPort, "HTTPS registration port")
	flag.IntVar(&o.TunnelPort, "tunnel-port", aissh.DefaultTunnelPort, "TLS tunnel port")
	flag.IntVar(&o.SSHPort, "ssh-port", 22, "local SSH service port")
	flag.StringVar(&o.CAFile, "ca", "", "custom server CA certificate; default uses bundled server certificate")
	flag.StringVar(&o.StateDir, "state-dir", filepath.Join(home, "aissh"), "local runtime directory (no device private key)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := aissh.RunAgent(ctx, o); e != nil {
		log.Fatal(e)
	}
}
