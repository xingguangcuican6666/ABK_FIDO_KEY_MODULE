package main

type HID interface {
	Read() ([]byte, error)
	Write([]byte) error
	Close() error
}
