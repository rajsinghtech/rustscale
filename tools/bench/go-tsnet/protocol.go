// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	magic             = "RSB1"
	headerLen         = 14
	ackLen            = 4
	goByte            = byte('G')
	modeThroughput    = byte(0)
	modeLatency       = byte(1)
	directionUp       = byte(0)
	directionDown     = byte(1)
	directionBidir    = byte(2)
	firehoseBufferLen = 1280
	readBufferLen     = 65535
	pingLen           = 8
)

type rsb1Header struct {
	mode            byte
	direction       byte
	durationSeconds uint32
	count           uint32
}

func (h rsb1Header) encode() [headerLen]byte {
	var value [headerLen]byte
	copy(value[:4], magic)
	value[4] = h.mode
	value[5] = h.direction
	binary.BigEndian.PutUint32(value[6:10], h.durationSeconds)
	binary.BigEndian.PutUint32(value[10:14], h.count)
	return value
}

func decodeHeader(value [headerLen]byte) (rsb1Header, error) {
	if string(value[:4]) != magic {
		return rsb1Header{}, errors.New("bad RSB1 magic")
	}
	return rsb1Header{
		mode:            value[4],
		direction:       value[5],
		durationSeconds: binary.BigEndian.Uint32(value[6:10]),
		count:           binary.BigEndian.Uint32(value[10:14]),
	}, nil
}

func writeHeader(w io.Writer, header rsb1Header) error {
	value := header.encode()
	return writeFull(w, value[:])
}

func readHeader(r io.Reader) (rsb1Header, error) {
	var value [headerLen]byte
	if _, err := io.ReadFull(r, value[:]); err != nil {
		return rsb1Header{}, err
	}
	return decodeHeader(value)
}

func writeAck(w io.Writer) error {
	return writeFull(w, []byte(magic))
}

func readAck(r io.Reader) error {
	var value [ackLen]byte
	if _, err := io.ReadFull(r, value[:]); err != nil {
		return err
	}
	if string(value[:]) != magic {
		return fmt.Errorf("bad RSB1 ACK magic %q", value)
	}
	return nil
}

func writeGo(w io.Writer) error {
	return writeFull(w, []byte{goByte})
}

func writeFull(w io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := w.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func readGo(r io.Reader) error {
	var value [1]byte
	if _, err := io.ReadFull(r, value[:]); err != nil {
		return err
	}
	if value[0] != goByte {
		return fmt.Errorf("bad RSB1 GO byte %#x", value[0])
	}
	return nil
}
