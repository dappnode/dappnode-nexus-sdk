// Package jsonutil contains the strict JSON parsing used at security boundaries.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DecodeStrict decodes exactly one JSON value and rejects unknown object fields.
func DecodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

// ReadAllLimited reads at most limit bytes. It rejects inputs that exceed the
// limit instead of silently truncating them.
func ReadAllLimited(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("negative read limit")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return data, nil
}
