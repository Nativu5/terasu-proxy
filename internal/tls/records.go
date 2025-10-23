package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"
)

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
)

var (
	// ErrNotHandshake indicates the record content type is not Handshake.
	ErrNotHandshake = errors.New("record is not a handshake")
	// ErrNotClientHello indicates the handshake message type is not ClientHello.
	ErrNotClientHello = errors.New("handshake is not a ClientHello")
	// ErrRecordTooLarge is returned when the TLS record exceeds the configured cap.
	ErrRecordTooLarge = errors.New("record exceeds configured limit")
	// ErrHandshakeTooShort signals the handshake payload is smaller than the minimum header.
	ErrHandshakeTooShort = errors.New("handshake record too short")
)

// Record represents a single TLS record payload.
type Record struct {
	ContentType uint8
	Version     uint16
	Payload     []byte
}

// ReadInitialRecord reads the first TLS record from conn with an optional timeout and size cap.
// It returns the parsed Record, the raw bytes read, and any error encountered.
func ReadInitialRecord(conn net.Conn, timeout time.Duration, maxSize int) (*Record, []byte, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() {
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	header := make([]byte, 5)
	total := make([]byte, 0, 5+maxSize)

	n, err := io.ReadFull(conn, header)
	total = append(total, header[:n]...)
	if err != nil {
		if len(total) == 0 {
			return nil, nil, err
		}
		return nil, total, err
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > maxSize {
		return nil, total, ErrRecordTooLarge
	}

	payload := make([]byte, length)
	m, err := io.ReadFull(conn, payload)
	total = append(total, payload[:m]...)
	if err != nil {
		return nil, total, err
	}

	record := &Record{
		ContentType: header[0],
		Version:     binary.BigEndian.Uint16(header[1:3]),
		Payload:     payload,
	}
	return record, append([]byte(nil), total...), nil
}

// WriteRecords emits one or more TLS records to conn with an optional random gap between the first two.
func WriteRecords(conn net.Conn, records []Record, gapMin, gapMax time.Duration) error {
	for idx, rec := range records {
		if err := rec.Write(conn); err != nil {
			return err
		}

		if idx == 0 && len(records) > 1 {
			gap := selectGapDuration(gapMin, gapMax)
			if gap > 0 {
				time.Sleep(gap)
			}
		}
	}
	return nil
}

// SplitClientHello divides a ClientHello handshake across one or two new TLS records.
func (rec *Record) SplitClientHello(first int) ([]Record, error) {
	if rec.ContentType != recordTypeHandshake {
		return nil, ErrNotHandshake
	}
	if len(rec.Payload) < 4 {
		return nil, ErrHandshakeTooShort
	}
	if rec.Payload[0] != handshakeTypeClientHello {
		return nil, ErrNotClientHello
	}

	bodyLength := int(rec.Payload[1])<<16 | int(rec.Payload[2])<<8 | int(rec.Payload[3])
	if bodyLength+4 != len(rec.Payload) {
		return nil, fmt.Errorf("handshake length mismatch: header=%d payload=%d", bodyLength, len(rec.Payload)-4)
	}

	if first <= 0 || first >= len(rec.Payload) {
		return []Record{{
			ContentType: rec.ContentType,
			Version:     rec.Version,
			Payload:     append([]byte(nil), rec.Payload...),
		}}, nil
	}

	firstPayload := append([]byte(nil), rec.Payload[:first]...)
	secondPayload := append([]byte(nil), rec.Payload[first:]...)

	return []Record{
		{ContentType: rec.ContentType, Version: rec.Version, Payload: firstPayload},
		{ContentType: rec.ContentType, Version: rec.Version, Payload: secondPayload},
	}, nil
}

// Write emits a single TLS record to conn using writev for zero-copy operation.
func (rec *Record) Write(conn net.Conn) error {
	length := len(rec.Payload)
	if length > 0xFFFF {
		return fmt.Errorf("record payload too large: %d", length)
	}
	header := []byte{
		rec.ContentType,
		byte(rec.Version >> 8),
		byte(rec.Version),
		byte(length >> 8),
		byte(length),
	}

	// Use net.Buffers to write header and payload in a single writev syscall
	buffers := net.Buffers{header, rec.Payload}
	if _, err := buffers.WriteTo(conn); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	return nil
}

func selectGapDuration(minDuration, maxDuration time.Duration) time.Duration {
	if maxDuration <= 0 {
		return 0
	}
	if minDuration < 0 {
		minDuration = 0
	}
	if maxDuration < minDuration {
		maxDuration = minDuration
	}
	span := maxDuration - minDuration
	if span <= 0 {
		return maxDuration
	}
	n := rand.Int63n(int64(span) + 1)
	return minDuration + time.Duration(n)
}
