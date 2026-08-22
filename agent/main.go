package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type session struct {
	aead    cipher.AEAD
	conn    net.Conn
	writeMu sync.Mutex
}

func newSession(conn net.Conn, pairing string) (*session, error) {
	clientNonce := make([]byte, 16)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, err
	}
	if _, err := conn.Write(clientNonce); err != nil {
		return nil, err
	}
	serverNonce := make([]byte, 16)
	if _, err := io.ReadFull(conn, serverNonce); err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(deriveKey(pairing, append(clientNonce, serverNonce...)))
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &session{aead: a, conn: conn}, nil
}

func deriveKey(password string, salt []byte) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(append(salt, 0, 0, 0, 1))
	t := mac.Sum(nil)
	out := append([]byte(nil), t...)
	for i := 1; i < 100000; i++ {
		mac = hmac.New(sha256.New, []byte(password))
		mac.Write(t)
		t = mac.Sum(nil)
		for j := range out {
			out[j] ^= t[j]
		}
	}
	return out
}

func (s *session) read() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(s.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 4096 {
		return nil, errors.New("frame too large")
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(s.conn, nonce); err != nil {
		return nil, err
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(s.conn, body); err != nil {
		return nil, err
	}
	return s.aead.Open(nil, nonce, body, nil)
}

func (s *session) write(p []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := s.aead.Seal(nil, nonce, p, nil)
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(sealed)))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(h[:]); err != nil {
		return err
	}
	if _, err := s.conn.Write(nonce); err != nil {
		return err
	}
	_, err := s.conn.Write(sealed)
	return err
}

func relay(conn net.Conn, pairing string, hid HID) error {
	s, err := newSession(conn, pairing)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		for {
			p, e := hid.Read()
			if e != nil {
				return
			}
			if len(p) == 64 {
				_ = s.write(p)
			}
		}
	}()
	for {
		p, e := s.read()
		if e != nil {
			return e
		}
		if len(p) != 64 {
			return errors.New("invalid CTAP packet")
		}
		if e = hid.Write(p); e != nil {
			return e
		}
	}
}

func main() {
	pairing := flag.String("pairing", "", "pairing code / PSK (required)")
	phone := flag.String("phone", "", "phone LAN address, e.g. 192.168.1.20:38741")
	flag.Parse()
	if *pairing == "" {
		log.Fatal("-pairing is required")
	}
	if *phone == "" {
		log.Fatal("-phone is required")
	}
	hid, err := NewHID("")
	if err != nil {
		log.Fatal(err)
	}
	defer hid.Close()
	for {
		conn, err := net.DialTimeout("tcp", *phone, 10*time.Second)
		if err != nil {
			log.Printf("phone connect: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if err := relay(conn, *pairing, hid); err != nil {
			log.Printf("session ended: %v", err)
		}
		time.Sleep(time.Second)
	}
}
