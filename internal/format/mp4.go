package format

import (
	"encoding/binary"
	"fmt"
	"math"
)

type MP4Parser struct{}

func (p *MP4Parser) Parse(fi *FormatInfo, data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("mp4: data too short")
	}
	offset := int64(0)
	dataLen := int64(len(data))
	fi.Type = FormatMP4
	var stack []BoxInfo
	depth := 0
	for offset+8 <= dataLen {
		boxSize := int64(binary.BigEndian.Uint32(data[offset : offset+4]))
		if boxSize == 0 {
			boxSize = dataLen - offset
		}
		typeBytes := data[offset+4 : offset+8]
		isValidType := true
		for _, c := range typeBytes {
			if c < 0x20 || c > 0x7e {
				isValidType = false
				break
			}
		}
		if !isValidType {
			offset += boxSize
			for len(stack) > 0 && offset >= stack[len(stack)-1].Offset+stack[len(stack)-1].Size {
				stack = stack[:len(stack)-1]
				depth--
			}
			continue
		}
		boxType := string(typeBytes)
		if boxSize < 8 {
			fi.AddAnomaly(offset, RiskHigh, "Box Underflow",
				fmt.Sprintf("box %s size %d < minimum 8", boxType, boxSize),
				"CVE-2023-49528")
			break
		}
		if boxSize > dataLen-offset {
			fi.AddAnomaly(offset, RiskMedium, "Box Overflow",
				fmt.Sprintf("box %s size %d exceeds remaining data %d", boxType, boxSize, dataLen-offset),
				"CVE-2022-3341")
			boxSize = dataLen - offset
		}
		bi := BoxInfo{Offset: offset, Size: boxSize, Type: boxType, Depth: depth}
		fi.RawBoxes = append(fi.RawBoxes, bi)
		fi.BoxCount++
		if boxType == "moov" {
			fi.HasMoov = true
			depth++
			stack = append(stack, bi)
			offset += 8
			continue
		}
		if boxType == "mdat" {
			fi.HasMdat = true
			offset += boxSize
			continue
		}
		if boxType == "trak" || boxType == "mdia" || boxType == "minf" ||
			boxType == "stbl" || boxType == "edts" || boxType == "udta" ||
			boxType == "meta" || boxType == "dinf" {
			depth++
			stack = append(stack, bi)
			offset += 8
			continue
		}
		if boxType == "stsz" || boxType == "stco" || boxType == "stsc" ||
			boxType == "stts" || boxType == "stss" || boxType == "co64" ||
			boxType == "ctts" || boxType == "sdtp" {
			p.parseStblBox(fi, data, offset, boxSize, boxType)
		}
		if boxType == "stsd" {
			p.parseStsd(fi, data, offset, boxSize)
		}
		if boxType == "avcC" || boxType == "hvcC" || boxType == "vpcC" ||
			boxType == "mp4a" || boxType == "esds" {
			p.parseCodecSpecific(fi, data, offset, boxSize, boxType)
		}
		if boxType == "trun" {
			p.parseTrun(fi, data, offset, boxSize)
		}
		offset += boxSize
		for len(stack) > 0 && offset >= stack[len(stack)-1].Offset+stack[len(stack)-1].Size {
			stack = stack[:len(stack)-1]
			depth--
		}
	}
	return nil
}

func (p *MP4Parser) parseStsd(fi *FormatInfo, data []byte, offset, boxSize int64) {
	if boxSize < 16 {
		return
	}
	innerOff := offset + 8
	remaining := boxSize - 8
	if remaining < 8 {
		return
	}
	entryCount := int(binary.BigEndian.Uint32(data[innerOff+4 : innerOff+8]))
	if entryCount <= 0 || entryCount > 128 {
		return
	}
	entriesOff := innerOff + 8
	entriesEnd := innerOff + remaining
	for i := 0; i < entryCount; i++ {
		if entriesOff+8 > entriesEnd {
			break
		}
		rawSize := int64(binary.BigEndian.Uint32(data[entriesOff : entriesOff+4]))
		fourCC := string(data[entriesOff+4 : entriesOff+8])
		if rawSize < 8 || entriesOff+rawSize > entriesEnd {
			break
		}
		fi.AddCodec(fourCC)
		if fourCC == "avc1" || fourCC == "hvc1" || fourCC == "hev1" {
			fi.Codec = fourCC
		}
		if fourCC == "av01" {
			fi.Codec = "av01"
		}
		entriesOff += rawSize
	}
}

func (p *MP4Parser) parseStblBox(fi *FormatInfo, data []byte, offset, boxSize int64, boxType string) {
	if boxSize < 12 {
		return
	}
	innerOff := offset + 8
	remaining := boxSize - 8
	switch boxType {
	case "stsz":
		if remaining < 8 {
			return
		}
		version := data[innerOff]
		_ = version
		sampleCount := int32(binary.BigEndian.Uint32(data[innerOff+4 : innerOff+8]))
		if sampleCount < 0 {
			fi.AddAnomaly(offset, RiskHigh, "Negative Sample Count",
				fmt.Sprintf("stsz sample_count=%d is negative", sampleCount),
				"CVE-2020-22015")
			return
		}
		if remaining >= 12 {
			entrySize := int32(binary.BigEndian.Uint32(data[innerOff+8 : innerOff+12]))
			if entrySize > 0 && sampleCount > math.MaxInt32/entrySize {
				fi.AddAnomaly(offset, RiskHigh, "Sample Size Overflow",
					fmt.Sprintf("stsz entry_size=%d * count=%d overflows", entrySize, sampleCount),
					"CVE-2020-22015")
			}
		}
	case "stco":
		if remaining < 8 {
			return
		}
		entryCount := int32(binary.BigEndian.Uint32(data[innerOff+4 : innerOff+8]))
		if entryCount > 1<<20 {
			fi.AddAnomaly(offset, RiskMedium, "Excessive Chunk Offsets",
				fmt.Sprintf("stco entry_count=%d exceeds sanity limit", entryCount),
				"")
			return
		}
		if remaining < 8+int64(entryCount)*4 {
			fi.AddAnomaly(offset, RiskHigh, "Chunk Offset Truncation",
				fmt.Sprintf("stco claims %d entries but only %d bytes remain", entryCount, remaining-8),
				"CVE-2020-22033")
		}
	case "stss":
		if remaining < 8 {
			return
		}
		entryCount := int32(binary.BigEndian.Uint32(data[innerOff+4 : innerOff+8]))
		if entryCount < 0 {
			fi.AddAnomaly(offset, RiskMedium, "Negative Sync Sample Count",
				fmt.Sprintf("stss entry_count=%d", entryCount), "")
		}
	}
}

func (p *MP4Parser) parseCodecSpecific(fi *FormatInfo, data []byte, offset, boxSize int64, boxType string) {
	if boxSize < 12 || boxSize > 1<<20 {
		fi.AddAnomaly(offset, RiskMedium, "Suspicious Extradata Size",
			fmt.Sprintf("%s size %d bytes", boxType, boxSize),
			"CVE-2021-38114")
		return
	}
	payloadSize := boxSize - 8
	if payloadSize > 1<<18 {
		fi.AddAnomaly(offset, RiskMedium, "Large Codec Configuration",
			fmt.Sprintf("%s payload %d bytes exceeds typical size", boxType, payloadSize), "")
	}
	switch boxType {
	case "avcC":
		if payloadSize < 4 {
			fi.AddAnomaly(offset, RiskMedium, "Truncated AVC Configuration",
				fmt.Sprintf("avcC size %d < minimum 4", payloadSize), "")
			return
		}
		innerOff := offset + 8
		_ = innerOff
	case "hvcC":
		if payloadSize < 23 {
			fi.AddAnomaly(offset, RiskMedium, "Truncated HEVC Configuration",
				fmt.Sprintf("hvcC size %d < minimum 23", payloadSize), "")
		}
	}
}

func (p *MP4Parser) parseTrun(fi *FormatInfo, data []byte, offset, boxSize int64) {
	if boxSize < 12 {
		fi.AddAnomaly(offset, RiskMedium, "Truncated trun Box",
			fmt.Sprintf("trun size %d < minimum 12", boxSize), "")
		return
	}
	innerOff := offset + 8
	flags := binary.BigEndian.Uint32(data[innerOff : innerOff+4])
	sampleCount := int32(binary.BigEndian.Uint32(data[innerOff+4 : innerOff+8]))
	if sampleCount < 1 || sampleCount > 100000 {
		fi.AddAnomaly(offset, RiskHigh, "Invalid trun Sample Count",
			fmt.Sprintf("trun sample_count=%d", sampleCount),
			"CVE-2021-38171")
		return
	}
	hasDataOffset := (flags >> 18) & 1
	hasFirstDur := (flags >> 17) & 1
	hasFirstSize := (flags >> 16) & 1
	_ = hasFirstDur
	_ = hasFirstSize
	if hasDataOffset == 1 {
		if boxSize < 16 {
			fi.AddAnomaly(offset, RiskMedium, "trun truncated (no data_offset)", "", "")
			return
		}
		dataOff := int32(binary.BigEndian.Uint32(data[innerOff+8 : innerOff+12]))
		if dataOff < 0 {
			fi.AddAnomaly(offset, RiskHigh, "Negative trun data_offset",
				fmt.Sprintf("trun data_offset=%d", dataOff),
				"CVE-2021-38171")
		}
	}
}

func (p *MP4Parser) HasMoov(fi *FormatInfo) bool {
	return fi.HasMoov
}

func (p *MP4Parser) BoxTree(fi *FormatInfo) string {
	if len(fi.RawBoxes) == 0 {
		return "(empty)"
	}
	result := ""
	for _, b := range fi.RawBoxes {
		indent := ""
		for i := 0; i < b.Depth; i++ {
			indent += "  "
		}
		result += fmt.Sprintf("%s[%s] @%d sz=%d\n", indent, b.Type, b.Offset, b.Size)
	}
	return result
}
