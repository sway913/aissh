package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/fatedier/frp/aissh"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	o := aissh.ServerOptions{}
	flag.StringVar(&o.DataDir, "data-dir", ".aissh-server", "server state and TLS directory")
	flag.StringVar(&o.APIAddr, "api-addr", ":17443", "HTTPS automatic registration address")
	flag.StringVar(&o.AdminAddr, "admin-addr", "127.0.0.1:17500", "admin HTTP address; access through SSH forwarding")
	flag.IntVar(&o.TunnelPort, "tunnel-port", 17000, "frp TLS tunnel port")
	initTLS := flag.Bool("init-tls", false, "initialize TLS certificate and exit")
	host := flag.String("host", aissh.DefaultHost, "server IP or hostname for --init-tls")
	showVersion := flag.Bool("version", false, "print aissh version and commit")
	flag.Parse()
	if *showVersion {
		fmt.Println(aissh.VersionString())
		return
	}
	if *initTLS {
		if e := aissh.InitTLS(o.DataDir, *host); e != nil {
			log.Fatal(e)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := aissh.RunServer(ctx, o); e != nil {
		log.Fatal(e)
	}
}
