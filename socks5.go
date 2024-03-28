// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
//
// Package socks5 is a SOCKS5 server implementation.
// Based on https://github.com/tailscale/tailscale/blob/v1.56.1/net/socks5/socks5.go
// stripped of authentication support
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"
)

// NewSocks5Server creates new local SOCKS5 proxy server.
func NewSocks5Server(log *slog.Logger, port int) (*Socks5Server, error) {
	lis, err := net.Listen("tcp", fmt.Sprint(":", port))
	if err != nil {
		return nil, err
	}
	return &Socks5Server{
		URL: lis.Addr().String(),
		lis: lis,
		log: log.With("proxy", "socks5"),
	}, nil
}

// Serve runs the socks5 server
func (s *Socks5Server) Serve() error {
	return s.serve(s.lis)
}

// Close closes the underlying listener.
func (s *Socks5Server) Close() {
	_ = s.lis.Close()
}

// Socks5Server is a SOCKS5 proxy server.
type Socks5Server struct {
	// URL specifies the server's address
	URL string

	lis net.Listener
	log *slog.Logger
}

// serve accepts and handles incoming connections on the given listener.
func (s *Socks5Server) serve(l net.Listener) error {
	s.log.Debug("Proxy up", "addr", l.Addr().String())
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			conn := &Conn{clientConn: c, srv: s, log: s.log.With(
				"laddr", c.LocalAddr().String(),
				"raddr", c.RemoteAddr().String(),
			)}
			err := conn.Run()
			if err != nil {
				s.log.Debug("Client connection failed", "err", err)
			}
		}()
	}
}

// Conn is a SOCKS5 connection for client to reach
// server.
type Conn struct {
	// The struct is filled by each of the internal
	// methods in turn as the transaction progresses.
	srv        *Socks5Server
	clientConn net.Conn
	request    *request
	log        *slog.Logger
}

// Run starts the new connection.
func (c *Conn) Run() error {
	c.log.Debug("Serving request", "request", c.request, "conn", formatConn(c.clientConn))
	err := parseClientGreeting(c.clientConn)
	if err != nil {
		if _, err := c.clientConn.Write([]byte{socks5Version, noAcceptableAuth}); err != nil {
			c.log.Debug("Failed to write to conn", "err", err)
		}
		return err
	}
	_, err = c.clientConn.Write([]byte{socks5Version, noAuthRequired})
	if err != nil {
		return fmt.Errorf("writing to conn: %w", err)
	}
	return c.handleRequest()
}

func (c *Conn) handleRequest() error {
	req, err := parseClientRequest(c.clientConn)
	if err != nil {
		res := &response{reply: generalFailure}
		buf, _ := res.marshal()
		if _, err := c.clientConn.Write(buf); err != nil {
			c.log.Debug("Failed to write to conn", "err", err)
		}
		return err
	}
	if req.command != connect {
		res := &response{reply: commandNotSupported}
		buf, _ := res.marshal()
		if _, err := c.clientConn.Write(buf); err != nil {
			c.log.Debug("Failed to write to conn.", "err", err)
		}
		return fmt.Errorf("unsupported command %v", req.command)
	}
	c.request = req

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv, err := c.srv.dial(
		ctx,
		"tcp",
		net.JoinHostPort(c.request.destination, strconv.Itoa(int(c.request.port))),
	)
	if err != nil {
		res := &response{reply: generalFailure}
		buf, _ := res.marshal()
		if _, err := c.clientConn.Write(buf); err != nil {
			c.log.Debug("Failed to write to conn", "err", err)
		}
		return err
	}
	defer srv.Close()
	serverAddr, serverPortStr, err := net.SplitHostPort(srv.LocalAddr().String())
	if err != nil {
		return err
	}
	serverPort, _ := strconv.Atoi(serverPortStr)

	var bindAddrType addrType
	if ip := net.ParseIP(serverAddr); ip != nil {
		if ip.To4() != nil {
			bindAddrType = ipv4
		} else {
			bindAddrType = ipv6
		}
	} else {
		bindAddrType = domainName
	}
	res := &response{
		reply:        success,
		bindAddrType: bindAddrType,
		bindAddr:     serverAddr,
		bindPort:     uint16(serverPort),
	}
	buf, err := res.marshal()
	if err != nil {
		res = &response{reply: generalFailure}
		buf, _ = res.marshal()
	}
	if _, err := c.clientConn.Write(buf); err != nil {
		return fmt.Errorf("writing to conn: %w", err)
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c.clientConn, srv)
		if err != nil {
			err = fmt.Errorf("from backend to client: %w", err)
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(srv, c.clientConn)
		if err != nil {
			err = fmt.Errorf("from client to backend: %w", err)
		}
		errc <- err
	}()
	return <-errc
}

func (s *Socks5Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// parseClientGreeting parses a request initiation packet.
func parseClientGreeting(r io.Reader) error {
	var hdr [2]byte
	_, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return fmt.Errorf("reading packet header: %w", err)
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("incompatible SOCKS version %b", hdr[0])
	}
	count := int(hdr[1])
	methods := make([]byte, count)
	_, err = io.ReadFull(r, methods)
	if err != nil {
		return fmt.Errorf("reading auth methods: %w", err)
	}
	for _, m := range methods {
		if m == noAuthRequired {
			return nil
		}
	}
	return fmt.Errorf("no acceptable auth methods")
}

func (r *request) String() string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("request(cmd=%s,dst=%s,port=%d,dst_addr=%s)",
		r.command, r.destination, r.port, r.destAddrType)
}

// request represents data contained within a SOCKS5
// connection request packet.
type request struct {
	command      commandType
	destination  string
	port         uint16
	destAddrType addrType
}

// parseClientRequest converts raw packet bytes into a
// SOCKS5Request struct.
func parseClientRequest(r io.Reader) (*request, error) {
	var hdr [4]byte
	_, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return nil, fmt.Errorf("reading packet header: %w", err)
	}
	cmd := hdr[1]
	destAddrType := addrType(hdr[3])

	var destination string
	var port uint16

	if destAddrType == ipv4 {
		var ip [4]byte
		_, err = io.ReadFull(r, ip[:])
		if err != nil {
			return nil, fmt.Errorf("reading IPv4 address: %w", err)
		}
		destination = net.IP(ip[:]).String()
	} else if destAddrType == domainName {
		var dstSizeByte [1]byte
		_, err = io.ReadFull(r, dstSizeByte[:])
		if err != nil {
			return nil, fmt.Errorf("reading domain name size: %w", err)
		}
		dstSize := int(dstSizeByte[0])
		domainName := make([]byte, dstSize)
		_, err = io.ReadFull(r, domainName)
		if err != nil {
			return nil, fmt.Errorf("reading domain name: %w", err)
		}
		destination = string(domainName)
	} else {
		return nil, fmt.Errorf("unsupported address type %v", destAddrType)
	}
	var portBytes [2]byte
	_, err = io.ReadFull(r, portBytes[:])
	if err != nil {
		return nil, fmt.Errorf("reading port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBytes[:])

	return &request{
		command:      commandType(cmd),
		destination:  destination,
		port:         port,
		destAddrType: destAddrType,
	}, nil
}

// response contains the contents of
// a response packet sent from the proxy
// to the client.
type response struct {
	reply        replyCode
	bindAddrType addrType
	bindAddr     string
	bindPort     uint16
}

// marshal converts a SOCKS5Response struct into
// a packet. If res.reply == Success, it may throw an error on
// receiving an invalid bind address. Otherwise, it will not throw.
func (res *response) marshal() ([]byte, error) {
	pkt := make([]byte, 4)
	pkt[0] = socks5Version
	pkt[1] = byte(res.reply)
	pkt[2] = 0 // null reserved byte
	pkt[3] = byte(res.bindAddrType)

	if res.reply != success {
		return pkt, nil
	}

	var addr []byte
	switch res.bindAddrType {
	case ipv4:
		addr = net.ParseIP(res.bindAddr).To4()
		if addr == nil {
			return nil, fmt.Errorf("invalid IPv4 address for binding")
		}
	case domainName:
		if len(res.bindAddr) > 255 {
			return nil, fmt.Errorf("invalid domain name for binding")
		}
		addr = make([]byte, 0, len(res.bindAddr)+1)
		addr = append(addr, byte(len(res.bindAddr)))
		addr = append(addr, []byte(res.bindAddr)...)
	default:
		return nil, fmt.Errorf("unsupported address type")
	}

	pkt = append(pkt, addr...)
	pkt = binary.BigEndian.AppendUint16(pkt, res.bindPort)

	return pkt, nil
}

func formatConn(c net.Conn) string {
	if c == nil {
		return "<nil>"
	}
	var localAddr, remoteAddr string
	if laddr := c.LocalAddr(); laddr != nil {
		localAddr = laddr.String()
	}
	if raddr := c.RemoteAddr(); raddr != nil {
		remoteAddr = raddr.String()
	}
	return fmt.Sprintf("conn(laddr=%s,raddr=%s)", localAddr, remoteAddr)
}

// socks5Version is the byte that represents the SOCKS version
// in requests.
const socks5Version byte = 5

func (r commandType) String() string {
	switch r {
	case connect:
		return "connect"
	case bind:
		return "bind"
	case udpAssociate:
		return "udp_assoc"
	default:
		return fmt.Sprint("unknown(", byte(r), ")")
	}
}

// commandType are the bytes sent in SOCKS5 packets
// that represent the kind of connection the client needs.
type commandType byte

// The set of valid SOCKS5 commands as described in RFC 1928.
const (
	connect      commandType = 1
	bind         commandType = 2
	udpAssociate commandType = 3
)

func (r addrType) String() string {
	switch r {
	case ipv4:
		return "ipv4"
	case domainName:
		return "domain"
	case ipv6:
		return "ipv6"
	default:
		return fmt.Sprint("unknown(", byte(r), ")")
	}
}

// addrType are the bytes sent in SOCKS5 packets
// that represent particular address types.
type addrType byte

// The set of valid SOCKS5 address types as defined in RFC 1928.
const (
	ipv4       addrType = 1
	domainName addrType = 3
	ipv6       addrType = 4
)

// replyCode are the bytes sent in SOCKS5 packets
// that represent replies from the server to a client
// request.
type replyCode byte

// The subset of valid SOCKS5 reply types as per the RFC 1928.
const (
	success             replyCode = 0
	generalFailure      replyCode = 1
	commandNotSupported replyCode = 7
)

// Authentication METHODs described in RFC 1928, section 3.
const (
	noAuthRequired   byte = 0
	noAcceptableAuth byte = 255
)
