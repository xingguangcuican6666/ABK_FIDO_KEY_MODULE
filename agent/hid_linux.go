//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Linux UHID event constants and the fixed-size create/input/output events.
const (
	uhidCreate2 = 11
	uhidInput2  = 12
	uhidOutput  = 6
	uhidStart   = 3
	uhidDestroy = 1
)

type linuxHID struct{ f *os.File }

func NewHID(device string) (HID, error) {
	u, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	h := &linuxHID{f: u}
	name := [128]byte{}
	copy(name[:], []byte("ABK FIDO2 Security Key"))
	rd := []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0, 0x26, 0xff, 0, 0x75, 8, 0x95, 0x40, 0x81, 2, 0x09, 0x21, 0x15, 0, 0x26, 0xff, 0, 0x75, 8, 0x95, 0x40, 0x91, 2, 0xc0}
	// struct uhid_event { u32 type; union { struct uhid_create2_req create2; } }.
	b := make([]byte, 4+4372)
	binary.LittleEndian.PutUint32(b, uhidCreate2)
	copy(b[4:], name[:])
	binary.LittleEndian.PutUint16(b[4+256:], uint16(len(rd)))
	binary.LittleEndian.PutUint16(b[4+258:], 0x03)
	binary.LittleEndian.PutUint32(b[4+260:], 0xABCD)
	binary.LittleEndian.PutUint32(b[4+264:], 0xF1D02)
	binary.LittleEndian.PutUint32(b[4+268:], 1)
	copy(b[4+276:], rd)
	if _, err = u.Write(b); err != nil {
		u.Close()
		return nil, err
	}
	return h, nil
}
func (h *linuxHID) Close() error { return h.f.Close() }
func (h *linuxHID) Read() ([]byte, error) {
	b := make([]byte, 4380)
	n, e := h.f.Read(b)
	if e != nil {
		return nil, e
	}
	if n < 4 {
		return nil, fmt.Errorf("short UHID event")
	}
	if binary.LittleEndian.Uint32(b) == uint32(uhidOutput) {
		size := binary.LittleEndian.Uint16(b[4+4096:])
		if size < 64 {
			return nil, fmt.Errorf("short HID output")
		}
		return append([]byte(nil), b[4:4+64]...), nil
	}
	return nil, fmt.Errorf("unexpected UHID event")
}
func (h *linuxHID) Write(p []byte) error {
	b := make([]byte, 4+2+4096)
	binary.LittleEndian.PutUint32(b, uint32(uhidInput2))
	binary.LittleEndian.PutUint16(b[4:6], uint16(len(p)))
	copy(b[6:], p)
	_, e := h.f.Write(b)
	return e
}
