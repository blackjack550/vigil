package format

import (
	"encoding/binary"
	"fmt"
	"math"
)

type MKVParser struct{}

func (p *MKVParser) Parse(fi *FormatInfo, data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("mkv: data too short")
	}
	fi.Type = FormatMKV
	if data[0] != 0x1a || data[1] != 0x45 || data[2] != 0xdf || data[3] != 0xa3 {
		return fmt.Errorf("mkv: invalid EBML header signature")
	}
	offset, err := p.parseEBMLHeader(fi, data, 0)
	if err != nil {
		return err
	}
	if offset < 0 || offset >= int64(len(data)) {
		return nil
	}
	p.parseSegment(fi, data, offset)
	return nil
}

func (p *MKVParser) readEBMLElement(data []byte, offset int64) (id uint64, idLen int, size uint64, sizeLen int, err error) {
	if offset >= int64(len(data)) {
		return 0, 0, 0, 0, fmt.Errorf("mkv: offset beyond data")
	}
	id, idLen = p.readEBMLVarint(data, offset)
	if idLen <= 0 || id == 0 {
		return 0, 0, 0, 0, fmt.Errorf("mkv: invalid element ID at %d", offset)
	}
	next := offset + int64(idLen)
	if next >= int64(len(data)) {
		return id, idLen, 0, 0, fmt.Errorf("mkv: truncated element")
	}
	varintStart := data[next:]
	if len(varintStart) == 0 {
		return id, idLen, 0, 0, fmt.Errorf("mkv: no size available")
	}
	sizeMarker := varintStart[0]
	sizeLen = 0
	for i := 0; i < 8; i++ {
		if sizeMarker&(0x80>>i) != 0 {
			sizeLen = i + 1
			break
		}
	}
	if sizeLen == 0 {
		return id, idLen, 0, 0, fmt.Errorf("mkv: invalid size marker 0x%02x", sizeMarker)
	}
	if int64(sizeLen) > int64(len(varintStart)) {
		return id, idLen, 0, 0, fmt.Errorf("mkv: truncated size")
	}
	size = uint64(sizeMarker & (0x7f >> (sizeLen - 1)))
	for i := 1; i < sizeLen; i++ {
		size = (size << 8) | uint64(varintStart[i])
	}
	if size == math.MaxUint64 {
		size = 0
	}
	return id, idLen, size, sizeLen, nil
}

func (p *MKVParser) readEBMLVarint(data []byte, offset int64) (uint64, int) {
	if offset >= int64(len(data)) {
		return 0, 0
	}
	first := data[offset]
	if first == 0 {
		return 0, 0
	}
	length := 0
	for i := 0; i < 8; i++ {
		if first&(0x80>>i) != 0 {
			length = i + 1
			break
		}
	}
	if length == 0 || length > 8 {
		return 0, 0
	}
	if offset+int64(length) > int64(len(data)) {
		return 0, 0
	}
	value := uint64(first & (0x7f >> (length - 1)))
	for i := 1; i < length; i++ {
		value = (value << 8) | uint64(data[offset+int64(i)])
	}
	return value, length
}

func (p *MKVParser) parseEBMLHeader(fi *FormatInfo, data []byte, offset int64) (int64, error) {
	id, idLen, size, _, err := p.readEBMLElement(data, offset)
	if err != nil {
		return 0, err
	}
	if id != 0x1A45DFA3 {
		return 0, fmt.Errorf("mkv: expected EBML header ID 0x1A45DFA3, got 0x%X", id)
	}
	contentStart := offset + int64(idLen) + int64(p.sizeLen(data, offset+int64(idLen)))
	if contentStart < 0 || contentStart >= int64(len(data)) {
		return 0, fmt.Errorf("mkv: EBML header content out of range")
	}
	end := contentStart + int64(size)
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	pos := contentStart
	for pos+2 <= end {
		elemID, elemIDLen, elemSize, _, err := p.readEBMLElement(data, pos)
		if err != nil {
			break
		}
		elemEnd := pos + int64(elemIDLen) + int64(p.sizeLen(data, pos+int64(elemIDLen))) + int64(elemSize)
		if elemEnd > end {
			elemEnd = end
		}
		switch elemID {
		case 0x4282:
			if elemSize >= 1 && elemSize <= 8 {
				val := p.readUint(data, pos+int64(elemIDLen)+int64(p.sizeLen(data, pos+int64(elemIDLen))), int(elemSize))
				if val > 0 && val < 2 {
				}
			}
		case 0x4286:
			if elemSize > 64 {
				fi.AddAnomaly(pos, RiskLow, "Long EBMLVersion Element",
					fmt.Sprintf("EBMLVersion size=%d", elemSize), "")
			}
		case 0x42F7:
			if elemSize > 64 {
				fi.AddAnomaly(pos, RiskLow, "Long EBMLMaxSizeLength Element",
					fmt.Sprintf("EBMLMaxSizeLength size=%d", elemSize), "")
			}
		case 0x42F2:
			if elemSize == 1 || elemSize == 2 || elemSize == 4 || elemSize == 8 {
				val := p.readUint(data, pos+int64(elemIDLen)+int64(p.sizeLen(data, pos+int64(elemIDLen))), int(elemSize))
				if val < 1 || val > 8 {
					fi.AddAnomaly(pos, RiskMedium, "Invalid EBMLMaxSizeLength",
						fmt.Sprintf("EBMLMaxSizeLength=%d (valid: 1-8)", val), "")
				}
			}
		}
		pos = elemEnd
	}
	segmentOff := end
	return segmentOff, nil
}

func (p *MKVParser) sizeLen(data []byte, offset int64) int {
	if offset >= int64(len(data)) {
		return 0
	}
	first := data[offset]
	for i := 0; i < 8; i++ {
		if first&(0x80>>i) != 0 {
			return i + 1
		}
	}
	return 0
}

func (p *MKVParser) parseSegment(fi *FormatInfo, data []byte, offset int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return
	}
	id, idLen, size, _, err := p.readEBMLElement(data, offset)
	if err != nil || id != 0x18538067 {
		fi.AddAnomaly(offset, RiskMedium, "Missing Segment Element",
			"Expected Segment (0x18538067) after EBML header", "")
		return
	}
	contentStart := offset + int64(idLen) + int64(p.sizeLen(data, offset+int64(idLen)))
	if contentStart < 0 || contentStart >= int64(len(data)) {
		return
	}
	end := contentStart + int64(size)
	if size == 0 || end > int64(len(data)) || end < contentStart {
		end = int64(len(data))
	}
	pos := contentStart
	infoDone := false
	tracksDone := false
	for pos+2 <= end {
		elemID, elemIDLen, elemSize, _, err := p.readEBMLElement(data, pos)
		if err != nil || elemIDLen <= 0 {
			break
		}
		if elemSize > uint64(end-pos) {
			elemSize = uint64(end - pos)
		}
		elemDataStart := pos + int64(elemIDLen) + int64(p.sizeLen(data, pos+int64(elemIDLen)))
		elemEnd := elemDataStart + int64(elemSize)
		if elemEnd > end {
			elemEnd = end
		}
		switch elemID {
		case 0x1549A966:
			if !infoDone {
				p.parseSegmentInfo(fi, data, elemDataStart, int64(elemSize))
				infoDone = true
			}
		case 0x1654AE6B:
			if !tracksDone {
				p.parseTracks(fi, data, elemDataStart, int64(elemSize))
				tracksDone = true
			}
		case 0x1F43B675:
			if int64(elemSize) > 1<<28 {
				fi.AddAnomaly(pos, RiskMedium, "Very Large Cluster",
					fmt.Sprintf("Cluster size %d bytes > 256MB", elemSize),
					"CVE-2022-3341")
			}
		case 0x1C53BB6B:
			if int64(elemSize) > 1<<24 {
				fi.AddAnomaly(pos, RiskLow, "Large Cues Element",
					fmt.Sprintf("Cues size %d bytes", elemSize), "")
			}
		case 0x1941A469:
		case 0x1043A770:
		case 0x114D9B74:
		case 0x1B538667:
		default:
			if pos == contentStart && elemID == 0 && elemIDLen == 0 {
				break
			}
		}
		pos = elemEnd
	}
	if !infoDone {
		fi.AddAnomaly(offset, RiskLow, "Missing SegmentInfo",
			"No SegmentInfo element found in Segment", "")
	}
	if !tracksDone {
		fi.AddAnomaly(offset, RiskLow, "Missing Tracks Element",
			"No Tracks element found in Segment", "")
	}
}

func (p *MKVParser) parseSegmentInfo(fi *FormatInfo, data []byte, offset int64, size int64) {
	end := offset + size
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	pos := offset
	for pos+2 <= end {
		elemID, elemIDLen, elemSize, _, err := p.readEBMLElement(data, pos)
		if err != nil || elemIDLen <= 0 {
			break
		}
		elemDataStart := pos + int64(elemIDLen) + int64(p.sizeLen(data, pos+int64(elemIDLen)))
		elemEnd := elemDataStart + int64(elemSize)
		if elemEnd > end || elemEnd < pos {
			elemEnd = end
		}
		switch elemID {
		case 0x2AD7B1:
			if elemSize <= 8 {
				durRaw := p.readFloat(data, elemDataStart, int(elemSize))
				if durRaw >= 0 && durRaw < 1<<20 {
					fi.Duration = durRaw
				}
			}
		case 0x4489:
			if int64(elemSize) > 64 {
				fi.AddAnomaly(pos, RiskLow, "Long Segment Duration Element",
					fmt.Sprintf("Duration size=%d", elemSize), "")
			}
		case 0x4D80:
			if elemSize < 0 || int64(elemSize) > 1<<10 {
				fi.AddAnomaly(pos, RiskLow, "Suspicious MuxingApp Size",
					fmt.Sprintf("MuxingApp element size=%d", elemSize), "")
			}
		case 0x5741:
			if int64(elemSize) > 1<<10 {
				fi.AddAnomaly(pos, RiskLow, "Suspicious WritingApp Size",
					fmt.Sprintf("WritingApp element size=%d", elemSize), "")
			}
		}
		pos = elemEnd
	}
}

func (p *MKVParser) parseTracks(fi *FormatInfo, data []byte, offset int64, size int64) {
	end := offset + size
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	pos := offset
	trackCount := 0
	for pos+2 <= end {
		elemID, elemIDLen, elemSize, _, err := p.readEBMLElement(data, pos)
		if err != nil || elemIDLen <= 0 {
			break
		}
		if elemID != 0xAE {
			pos += int64(elemIDLen) + int64(p.sizeLen(data, pos+int64(elemIDLen))) + int64(elemSize)
			continue
		}
		trackCount++
		if trackCount > 128 {
			fi.AddAnomaly(pos, RiskMedium, "Excessive Track Count",
				fmt.Sprintf("MKV has > 128 tracks"), "")
			break
		}
		elemDataStart := pos + int64(elemIDLen) + int64(p.sizeLen(data, pos+int64(elemIDLen)))
		elemEnd := elemDataStart + int64(elemSize)
		if elemEnd > end {
			elemEnd = end
		}
		p.parseTrackEntry(fi, data, elemDataStart, elemEnd-elemDataStart)
		pos = elemEnd
	}
	fi.Streams = trackCount
}

func (p *MKVParser) parseTrackEntry(fi *FormatInfo, data []byte, offset int64, size int64) {
	end := offset + size
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	pos := offset
	var trackType uint64
	var codecID string
	for pos+2 <= end {
		elemID, elemIDLen, elemSize, _, err := p.readEBMLElement(data, pos)
		if err != nil || elemIDLen <= 0 {
			break
		}
		elemDataStart := pos + int64(elemIDLen) + int64(p.sizeLen(data, pos+int64(elemIDLen)))
		elemEnd := elemDataStart + int64(elemSize)
		if elemEnd > end {
			elemEnd = end
		}
		switch elemID {
		case 0xD7:
			if elemSize == 1 {
				trackType = p.readUint(data, elemDataStart, int(elemSize))
			}
		case 0x86:
			if int64(elemSize) < 32 {
				if elemDataStart+int64(elemSize) <= int64(len(data)) {
					codecID = string(data[elemDataStart : elemDataStart+int64(elemSize)])
					fi.AddCodec(codecID)
				}
			}
			if int64(elemSize) > 128 {
				fi.AddAnomaly(pos, RiskLow, "Long CodecID",
					fmt.Sprintf("CodecID size=%d", elemSize), "")
			}
		case 0xE0:
			p.parseVideoTrack(fi, data, elemDataStart, int64(elemSize))
		case 0xE1:
			if int64(elemSize) > 1<<20 {
				fi.AddAnomaly(pos, RiskMedium, "Large Audio Element",
					fmt.Sprintf("Audio element size=%d", elemSize), "")
			}
		case 0x63C0:
			if int64(elemSize) > 1<<12 {
				fi.AddAnomaly(pos, RiskLow, "Large ContentEncodings",
					fmt.Sprintf("ContentEncodings size=%d", elemSize), "")
			}
		case 0x23E383:
			if int64(elemSize) > 256 {
				fi.AddAnomaly(pos, RiskLow, "Large DefaultDuration",
					fmt.Sprintf("DefaultDuration size=%d", elemSize), "")
			}
		case 0x536E:
			if int64(elemSize) > 64 {
				fi.AddAnomaly(pos, RiskLow, "Large Name Element",
					fmt.Sprintf("Name element size=%d", elemSize), "")
			}
		case 0x22B59C:
			if int64(elemSize) > 64 {
				fi.AddAnomaly(pos, RiskLow, "Large Language Element",
					fmt.Sprintf("Language element size=%d", elemSize), "")
			}
		}
		pos = elemEnd
	}
	if trackType == 1 {
		fi.Codec = codecID
	}
}

func (p *MKVParser) parseVideoTrack(fi *FormatInfo, data []byte, offset int64, size int64) {
	end := offset + size
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	pos := offset
	for pos+2 <= end {
		elemID, elemIDLen, elemSize, _, err := p.readEBMLElement(data, pos)
		if err != nil || elemIDLen <= 0 {
			break
		}
		elemDataStart := pos + int64(elemIDLen) + int64(p.sizeLen(data, pos+int64(elemIDLen)))
		elemEnd := elemDataStart + int64(elemSize)
		if elemEnd > end || elemEnd < pos {
			elemEnd = end
		}
		switch elemID {
		case 0xB0:
			if elemSize <= 4 {
				val := p.readUint(data, elemDataStart, int(elemSize))
				if val > 0 && val <= 1<<15 {
					fi.Width = int(val)
				} else if val > 1<<15 {
					fi.AddAnomaly(pos, RiskMedium, "Suspicious Video Width",
						fmt.Sprintf("PixelWidth=%d exceeds normal range", val), "")
				}
			}
		case 0xBA:
			if elemSize <= 4 {
				val := p.readUint(data, elemDataStart, int(elemSize))
				if val > 0 && val <= 1<<15 {
					fi.Height = int(val)
				} else if val > 1<<15 {
					fi.AddAnomaly(pos, RiskMedium, "Suspicious Video Height",
						fmt.Sprintf("PixelHeight=%d exceeds normal range", val), "")
				}
			}
		case 0x2383E3:
			_ = elemSize
		case 0x2F:
		}
		pos = elemEnd
	}
}

func (p *MKVParser) readUint(data []byte, offset int64, size int) uint64 {
	if offset < 0 || size <= 0 || size > 8 || offset+int64(size) > int64(len(data)) {
		return 0
	}
	var val uint64
	for i := 0; i < size; i++ {
		val = (val << 8) | uint64(data[offset+int64(i)])
	}
	return val
}

func (p *MKVParser) readFloat(data []byte, offset int64, size int) float64 {
	if offset < 0 || offset+int64(size) > int64(len(data)) {
		return 0
	}
	switch size {
	case 4:
		return float64(binary.BigEndian.Uint32(data[offset : offset+4]))
	case 8:
		bits := binary.BigEndian.Uint64(data[offset : offset+8])
		return math.Float64frombits(bits)
	}
	return 0
}
