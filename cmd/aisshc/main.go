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
	"runtime"
	"syscall"
)

func main() {
	o := aissh.AgentOptions{}
	flag.StringVar(&o.Host, "server", aissh.DefaultHost, "TLS tunnel server hostname")
	flag.StringVar(&o.APIURL, "api-url", aissh.DefaultAPIURL, "HTTPS registration URL")
	flag.IntVar(&o.TunnelPort, "tunnel-port", aissh.DefaultTunnelPort, "TLS tunnel port")
	flag.IntVar(&o.SSHPort, "ssh-port", 22, "local SSH service port")
	flag.StringVar(&o.CAFile, "ca", "", "custom tunnel CA certificate; default uses bundled trust root")
	flag.StringVar(&o.StateDir, "state-dir", "", "local runtime directory; default is the user config directory")
	foreground := flag.Bool("foreground", false, "run in terminal without installing boot startup")
	serviceRun := flag.Bool("service-run", false, "run the installed background client")
	serviceAction := flag.String("service", "", "startup management: status, update, uninstall")
	showVersion := flag.Bool("version", false, "print aissh version and commit")
	flag.Parse()
	if *showVersion {
		fmt.Println(aissh.VersionString())
		return
	}
	if !*serviceRun && o.StateDir == "" {
		home, err := os.UserConfigDir()
		if err != nil {
			log.Fatal(err)
		}
		o.StateDir = filepath.Join(home, "aissh")
	}
	if *serviceRun {
		c, err := aissh.LoadStartupConfig()
		if err != nil {
			log.Fatal(err)
		}
		o = c.Options
		o.ManagedIdentity = &c
		if runtime.GOOS == "windows" {
			if err := aissh.StartupLog(); err != nil {
				log.Fatal(err)
			}
		}
	} else if !*foreground || *serviceAction != "" {
		message, err := aissh.EnsureStartup(o, *serviceAction)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(message)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := aissh.RunAgent(ctx, o); e != nil {
		log.Fatal(e)
	}
}
