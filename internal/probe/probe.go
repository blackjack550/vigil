package probe

import (
	"fmt"
	"math"
	"os"
)

const (
	MaxHeaderSize = 1 << 20
	MaxProbeSize  = 64 << 20
	ChunkMaxSize  = 16 << 20
)

type SafeFile struct {
	File    *os.File
	Size    int64
	MaxRead int64
}

func OpenSafe(path string) (*SafeFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("probe: open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("probe: stat: %w", err)
	}
	maxRead := info.Size()
	if maxRead > MaxProbeSize {
		maxRead = MaxProbeSize
	}
	return &SafeFile{File: f, Size: info.Size(), MaxRead: maxRead}, nil
}

func (sf *SafeFile) Close() error {
	return sf.File.Close()
}

func (sf *SafeFile) ReadAt(buf []byte, offset int64) (int, error) {
	limit := sf.MaxRead
	if offset >= limit {
		return 0, fmt.Errorf("probe: offset %d beyond max read %d", offset, limit)
	}
	maxLen := limit - offset
	if int64(len(buf)) > maxLen {
		buf = buf[:maxLen]
	}
	if int64(len(buf)) > ChunkMaxSize {
		buf = buf[:ChunkMaxSize]
	}
	return sf.File.ReadAt(buf, offset)
}

func (sf *SafeFile) ReadBytes(offset int64, size int) ([]byte, error) {
	if size <= 0 || size > ChunkMaxSize {
		return nil, fmt.Errorf("probe: invalid read size %d", size)
	}
	if offset < 0 || offset >= sf.MaxRead {
		return nil, fmt.Errorf("probe: offset out of range")
	}
	if offset+int64(size) > sf.MaxRead {
		size = int(sf.MaxRead - offset)
	}
	buf := make([]byte, size)
	n, err := sf.ReadAt(buf, offset)
	if err != nil {
		return buf[:n], fmt.Errorf("probe: read: %w", err)
	}
	return buf[:n], nil
}

func (sf *SafeFile) ReadUint8(offset int64) (uint8, error) {
	b, err := sf.ReadBytes(offset, 1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (sf *SafeFile) ReadUint16BE(offset int64) (uint16, error) {
	b, err := sf.ReadBytes(offset, 2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (sf *SafeFile) ReadUint32BE(offset int64) (uint32, error) {
	b, err := sf.ReadBytes(offset, 4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func (sf *SafeFile) ReadUint64BE(offset int64) (uint64, error) {
	b, err := sf.ReadBytes(offset, 8)
	if err != nil {
		return 0, err
	}
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]), nil
}

func (sf *SafeFile) ReadUint16LE(offset int64) (uint16, error) {
	b, err := sf.ReadBytes(offset, 2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0]) | uint16(b[1])<<8, nil
}

func (sf *SafeFile) ReadUint32LE(offset int64) (uint32, error) {
	b, err := sf.ReadBytes(offset, 4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, nil
}

func (sf *SafeFile) ReadString(offset int64, size int) (string, error) {
	b, err := sf.ReadBytes(offset, size)
	if err != nil {
		return "", err
	}
	end := len(b)
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	return string(b[:end]), nil
}

func (sf *SafeFile) ReadFourCC(offset int64) (string, error) {
	b, err := sf.ReadBytes(offset, 4)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type FileInfo struct {
	Path       string
	Size       int64
	Header     []byte
	HeaderSize int
	Format     string
}

func ProbeFile(path string) (*FileInfo, error) {
	sf, err := OpenSafe(path)
	if err != nil {
		return nil, err
	}
	defer sf.Close()
	hdrSize := int64(256)
	if sf.Size < hdrSize {
		hdrSize = sf.Size
	}
	header, err := sf.ReadBytes(0, int(hdrSize))
	if err != nil {
		return nil, fmt.Errorf("probe: read header: %w", err)
	}
	return &FileInfo{
		Path:       path,
		Size:       sf.Size,
		Header:     header,
		HeaderSize: len(header),
	}, nil
}

func ReadFileSections(path string, sections []OffsetSize) (map[string][]byte, error) {
	sf, err := OpenSafe(path)
	if err != nil {
		return nil, err
	}
	defer sf.Close()
	result := make(map[string][]byte, len(sections))
	for _, s := range sections {
		b, err := sf.ReadBytes(s.Offset, s.Size)
		if err != nil {
			result[s.Name] = nil
			continue
		}
		result[s.Name] = b
	}
	return result, nil
}

type OffsetSize struct {
	Name   string
	Offset int64
	Size   int
}

func SafeAdd64(a, b int64) (int64, bool) {
	if a > math.MaxInt64-b {
		return 0, false
	}
	return a + b, true
}

func SafeAdd32(a, b int32) (int32, bool) {
	if a > math.MaxInt32-b {
		return 0, false
	}
	return a + b, true
}

func SafeMul32(a, b int32) (int32, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a > math.MaxInt32/b {
		return 0, false
	}
	return a * b, true
}
