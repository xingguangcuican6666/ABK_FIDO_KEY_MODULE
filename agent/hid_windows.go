//go:build windows

package main

import (
	"errors"
	"io"
	"os"
)

type windowsHID struct{ f *os.File }

func NewHID(device string) (HID, error) {
	if device == "" {
		device = `\\.\pipe\abk-fido-vhid`
	}
	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &windowsHID{f: f}, nil
}
func (h *windowsHID) Read() ([]byte, error) {
	p := make([]byte, 64)
	_, e := io.ReadFull(h.f, p)
	return p, e
}
func (h *windowsHID) Write(p []byte) error {
	if len(p) != 64 {
		return errors.New("invalid HID packet")
	}
	_, e := h.f.Write(p)
	return e
}
func (h *windowsHID) Close() error { return h.f.Close() }
