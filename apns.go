package apns

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type Notification struct {
	DeviceToken        string
	Identifier         uint32
	ExpireAfterSeconds int

	Payload *Payload
}

// An Apn contain a ErrorChan channle when connected to apple server. When a notification sent wrong, you can get the error infomation from this channel.
type Apn struct {
	ErrorChan <-chan error

	server  string
	conf    *tls.Config
	conn    *tls.Conn
	timeout time.Duration

	sendChan  	chan *sendArg
	errorChan 	chan error
	buffer 		int
	sentChan 	chan *sendArg
}

//Last value failed to retry in case of connection fail
var last_fail uint32

// New Apn with cert_filename and key_filename.
func New(cert_filename string, key_filename string, server string, timeout time.Duration, buffer int) (*Apn, error) {
	echan := make(chan error)

	cert, err := tls.LoadX509KeyPair(cert_filename, key_filename)
	if err != nil {
		return nil, err
	}
	nameport := strings.Split(server, ":")
	certificate := []tls.Certificate{cert}
	conf := &tls.Config{
		Certificates: certificate,
		ServerName:   nameport[0],
	}

	ret := &Apn{
		ErrorChan: echan,
		server:    server,
		conf:      conf,
		timeout:   timeout,
		sendChan:  make(chan *sendArg),
		errorChan: echan,
		buffer:    buffer,
		sentChan:  make(chan *sendArg, buffer),
	}

	go sendLoop(ret)
	return ret, err
}

func (a *Apn) GetErrorChan() <-chan error {
	return a.ErrorChan
}

// Send a notification to iOS
func (a *Apn) Send(notification *Notification) error {
	err := make(chan error)
	arg := &sendArg{
		n:   notification,
		err: err,
	}
	a.sendChan <- arg
	return <-err
}

type sendArg struct {
	n   *Notification
	err chan<- error
}

func (a *Apn) Close() error {
	if a.conn == nil {
		return nil
	}
	conn := a.conn
	a.conn = nil
	return conn.Close()
}

func (a *Apn) connect() (<-chan uint32, error) {
	// make sure last readError(...) will fail when reading.
	err := a.Close()
	if err != nil {
		return nil, fmt.Errorf("close last connection failed: %s", err)
	}

	conn, err := net.Dial("tcp", a.server)
	if err != nil {
		return nil, fmt.Errorf("connect to server error: %d", err)
	}

	var client_conn *tls.Conn = tls.Client(conn, a.conf)
	err = client_conn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("handshake server error: %s", err)
	}

	a.conn = client_conn
	quit := make(chan uint32)
	go readError(client_conn, quit, a.errorChan)

	return quit, nil
}

func (a *Apn) send(notification *Notification) error {
	tokenbin, err := hex.DecodeString(notification.DeviceToken)
	if err != nil {
		return fmt.Errorf("convert token to hex error: %s", err)
	}

	payloadbyte, _ := notification.Payload.MarshalJSON()
	expiry := time.Now().Add(time.Duration(notification.ExpireAfterSeconds) * time.Second).Unix()

	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, uint8(1))
	binary.Write(buffer, binary.BigEndian, uint32(notification.Identifier))
	binary.Write(buffer, binary.BigEndian, uint32(expiry))
	binary.Write(buffer, binary.BigEndian, uint16(len(tokenbin)))
	binary.Write(buffer, binary.BigEndian, tokenbin)
	binary.Write(buffer, binary.BigEndian, uint16(len(payloadbyte)))
	binary.Write(buffer, binary.BigEndian, payloadbyte)
	pushPackage := buffer.Bytes()

	_, err = a.conn.Write(pushPackage)
	if err != nil {
		return fmt.Errorf("write socket error: %s", err)
	}
	return nil
}

func sendLoop(apn *Apn) {
	for {
		arg := <-apn.sendChan
		quit, err := apn.connect()
		if err != nil {
			arg.err <- err
			continue
		}
		arg.err <- apn.send(arg.n)
		apn.addToSent(arg)

		for connected := true; connected; {
			select {
			case <-quit:
				connected = false
				go func(){
					for{
						elem := <-apn.sentChan
						if elem.n.Identifier==last_fail{
							break
						}
					}
					for i := 0; i<len(apn.sentChan); i++ {
				    	elem := <-apn.sentChan
				    	
				    	apn.Send(elem.n)
				    }
				}()
			case <-time.After(apn.timeout):
				connected = false
			case arg := <-apn.sendChan:
				arg.err <- apn.send(arg.n)
				apn.addToSent(arg)
			}
		}
		err = apn.Close()
		if err != nil {
			e := NewNotificationError(nil, err)
			apn.errorChan <- e
		}
	}
}

func (a *Apn) addToSent(arg *sendArg){
	if len(a.sentChan)>=a.buffer{
		//fmt.Printf("Buffer reached: size=%d , buffer=%d\n", len(a.sentChan), a.buffer)
		<-a.sentChan
	}
	a.sentChan <- arg
}

func readError(conn *tls.Conn, quit chan<- uint32, c chan<- error) {
	p := make([]byte, 6, 6)
	for {
		n, err := conn.Read(p)
		e := NewNotificationError(p[:n], err)
		fmt.Errorf("Read error in APNS : "+ e.Error())
		if e.OtherError==nil{
			last_fail = e.Identifier
		}
		c <- e
		if err != nil {
			quit <- 1
			return
		}
	}
}
