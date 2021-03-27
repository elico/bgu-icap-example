package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/asaskevich/govalidator"
	"github.com/elico/go-linux-tproxy"
)

// GlobalHTTPClients the map which hold the http client for use by tproxy
var GlobalHTTPClients = map[string]*http.Client{}

func noRedirect(req *http.Request, via []*http.Request) error {
	return errors.New("Don't redirect")
}

// CreateTproxyHTTPClient is creating a uniqe http  client per client source IP addres
func CreateTproxyHTTPClient(srcIP string) *http.Client {
	var netTransport = &http.Transport{
		Dial: (func(network, addr string) (net.Conn, error) {
			// Resolve address
			//if the address is an IP
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			switch {
			case govalidator.IsIP(host):
				srvConn, err := tproxy.TCPDial(srcIP, addr)
				if err != nil {
					return nil, err
				}
				return srvConn, nil
			case govalidator.IsDNSName(host):

				ips, err := net.LookupIP(host)
				if err != nil {
					return nil, err
				}
				for i, ip := range ips {
					srvConn, err := tproxy.TCPDial(srcIP, net.JoinHostPort(ip.String(), port))
					if err != nil {
						fmt.Println(err)
						if i == len(ips) {
							return srvConn, nil
						}
						continue
					}
					fmt.Println("returning a srvconn")
					return srvConn, nil
				}
				srvConn, err := tproxy.TCPDial(srcIP, addr)
				if err != nil {
					return nil, err
				}
				return srvConn, nil
			}
			return nil, nil
		}),
	}
	client := &http.Client{Transport: netTransport, CheckRedirect: noRedirect}
	return client
}
