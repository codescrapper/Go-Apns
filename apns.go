package apns

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
}

var sent_queue []*sendArg
var index_map map[uint32]int
var old_index_map map[uint32]int
var curr_idx int

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
	}

	sent_queue = make([]*sendArg, 2*ret.buffer)
	index_map = make(map[uint32]int)
	old_index_map = make(map[uint32]int)
	curr_idx = -1

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

func (a *Apn) connect() (<-chan int, error) {
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
	quit := make(chan int)
	go readError(client_conn, quit, a.errorChan)

	return quit, nil
}

func (a *Apn) send(notification *Notification) error {
	tokenbin, err := hex.DecodeString(notification.DeviceToken)
	if err != nil {
		return fmt.Errorf("convert token to hex error: %s", err)
	}

	payloadbyte, _ := json.Marshal(notification.Payload)
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

		for connected := true; connected; {
			select {
			case index := <-quit:
				if index!=-1{
					apn.clearBuffer(index)
					for _, arg := range sent_queue[index+1:]{
						apn.sendChan <- arg
					}
				}
				connected = false
			case <-time.After(apn.timeout):
				connected = false
			case arg := <-apn.sendChan:
				arg.err <- apn.send(arg.n)
				curr_idx = curr_idx+1
				sent_queue[curr_idx] = arg
				index_map[arg.n.Identifier] = curr_idx
				if curr_idx >= 2*apn.buffer{
					apn.clearBuffer(apn.buffer)
				}
			}
		}

		err = apn.Close()
		if err != nil {
			e := NewNotificationError(nil, err)
			apn.errorChan <- e
		}
	}
}

func (apn *Apn)clearBuffer(till int){
	curr_idx = len(sent_queue)-till+1
	sent_queue = append(sent_queue, sent_queue[till+1:]...)
	old_index_map = index_map
	index_map = make(map[uint32]int)
}

func readError(conn *tls.Conn, quit chan<- int, c chan<- error) {
	p := make([]byte, 6, 6)
	for {
		n, err := conn.Read(p)
		e := NewNotificationError(p[:n], err)
		c <- e
		if err != nil {
			index := -1
			var ok bool
			if e.OtherError==nil{
				identifier := e.Identifier
				if index, ok = index_map[identifier]; !ok{
					index, _ = old_index_map[identifier]
				}
			}
			quit <- index
			return
		}
	}
}
