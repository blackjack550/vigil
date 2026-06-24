package format

import (
	"encoding/binary"
	"fmt"
)

type AVIParser struct{}

func (p *AVIParser) Parse(fi *FormatInfo, data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("avi: data too short")
	}
	fi.Type = FormatAVI
	offset := int64(12)
	dataLen := int64(len(data))
	if string(data[0:4]) != "RIFF" || string(data[8:12]) != "AVI " {
		fi.AddAnomaly(0, RiskMedium, "Invalid RIFF Header",
			"AVI file must start with RIFF + AVI signature", "")
		return nil
	}
	riffSize := int64(binary.LittleEndian.Uint32(data[4:8]))
	if riffSize > dataLen-8 {
		fi.AddAnomaly(4, RiskMedium, "RIFF Size Exceeds File",
			fmt.Sprintf("RIFF size %d > file size %d", riffSize, dataLen-8), "")
		riffSize = dataLen - 8
	}
	p.parseChunks(fi, data, offset, riffSize)
	return nil
}

func (p *AVIParser) parseChunks(fi *FormatInfo, data []byte, offset, size int64) {
	end := offset + size
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	for offset+8 <= end {
		chunkID := string(data[offset : offset+4])
		chunkSize := int64(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		hdrl := byte(0)
		movi := byte(0)
		idx1 := byte(0)
		if chunkSize > 1<<31 || chunkSize < 0 {
			fi.AddAnomaly(offset, RiskHigh, "Invalid AVI Chunk Size",
				fmt.Sprintf("chunk %s size=%d", chunkID, chunkSize),
				"CVE-2022-3341")
			break
		}
		chunkEnd := offset + 8 + chunkSize
		if chunkEnd > end {
			if chunkID == "idx1" {
				chunkSize = end - offset - 8
				chunkEnd = end
			} else {
				fi.AddAnomaly(offset, RiskMedium, "AVI Chunk Truncated",
					fmt.Sprintf("chunk %s claims %d bytes but only %d remain",
						chunkID, chunkSize, end-offset-8), "")
				break
			}
		}
		switch chunkID {
		case "LIST":
			if chunkSize < 4 {
				fi.AddAnomaly(offset, RiskMedium, "Truncated LIST Chunk",
					fmt.Sprintf("LIST size %d < 4", chunkSize), "")
				offset += 8 + chunkSize
				continue
			}
			listType := string(data[offset+8 : offset+12])
			if listType == "hdrl" {
				hdrl = 1
				fi.AddAnomaly(offset, RiskLow, "Header List",
					"AVI header list found at expected position", "")
			} else if listType == "movi" {
				movi = 1
			}
			p.parseChunks(fi, data, offset+12, chunkSize-4)
		case "avih":
			if chunkSize >= 56 {
				p.parseMainHeader(fi, data, offset+8)
			} else {
				fi.AddAnomaly(offset, RiskMedium, "Truncated Main Header",
					fmt.Sprintf("avih size %d < 56", chunkSize), "")
			}
		case "strh":
			if chunkSize >= 56 {
				p.parseStreamHeader(fi, data, offset+8, chunkSize)
			} else {
				fi.AddAnomaly(offset, RiskMedium, "Truncated Stream Header",
					fmt.Sprintf("strh size %d < 56", chunkSize), "")
			}
		case "strf":
			if chunkSize < 40 {
				fi.AddAnomaly(offset, RiskMedium, "Truncated Stream Format",
					fmt.Sprintf("strf size %d < 40", chunkSize), "")
			} else {
				p.parseStreamFormat(fi, data, offset+8, chunkSize)
			}
		case "JUNK":
			if chunkSize > 1<<20 {
				fi.AddAnomaly(offset, RiskLow, "Large JUNK Chunk",
					fmt.Sprintf("JUNK chunk %d bytes > 1MB", chunkSize), "")
			}
		case "idx1":
			idx1 = 1
			p.parseIndex(fi, data, offset+8, chunkSize)
		default:
			if len(chunkID) == 4 {
				for _, c := range chunkID {
					if c < 0x20 || c > 0x7e {
						fi.AddAnomaly(offset, RiskMedium, "Non-printable Chunk ID",
							fmt.Sprintf("chunk ID %q has non-printable chars", chunkID), "")
						break
					}
				}
			}
		}
		if chunkSize%2 == 1 {
			chunkSize++
		}
		offset += 8 + chunkSize
		if hdrl != 0 || movi != 0 || idx1 != 0 {
		}
	}
}

func (p *AVIParser) parseMainHeader(fi *FormatInfo, data []byte, offset int64) {
	if int64(len(data)) < offset+56 {
		return
	}
	dwMicroSecPerFrame := binary.LittleEndian.Uint32(data[offset : offset+4])
	dwMaxBytesPerSec := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
	dwFlags := binary.LittleEndian.Uint32(data[offset+12 : offset+16])
	dwTotalFrames := binary.LittleEndian.Uint32(data[offset+16 : offset+20])
	dwStreams := binary.LittleEndian.Uint32(data[offset+24 : offset+28])
	dwWidth := binary.LittleEndian.Uint32(data[offset+40 : offset+44])
	dwHeight := binary.LittleEndian.Uint32(data[offset+44 : offset+48])
	fi.Streams = int(dwStreams)
	if dwWidth > 0 && dwWidth <= 1<<15 {
		fi.Width = int(dwWidth)
	}
	if dwHeight > 0 && dwHeight <= 1<<15 {
		fi.Height = int(dwHeight)
	}
	if dwMicroSecPerFrame == 0 {
		fi.AddAnomaly(offset, RiskMedium, "Zero Frame Duration",
			"dwMicroSecPerFrame=0 in main AVI header", "")
	}
	if dwTotalFrames == 0 && dwFlags&0x10 == 0 {
		fi.AddAnomaly(offset, RiskLow, "Zero Total Frames",
			"dwTotalFrames=0 without AVIF_COPYRIGHTED flag", "")
	}
	if dwMaxBytesPerSec == 0 {
		fi.AddAnomaly(offset, RiskLow, "Zero Max Data Rate",
			"dwMaxBytesPerSec=0 in main AVI header", "")
	}
	if dwFlags&^0x10DF != 0 {
		fi.AddAnomaly(offset, RiskLow, "Unknown AVI Flags",
			fmt.Sprintf("dwFlags=0x%x contains unknown bits", dwFlags), "")
	}
	if dwStreams > 32 {
		fi.AddAnomaly(offset, RiskMedium, "Excessive Stream Count",
			fmt.Sprintf("dwStreams=%d exceeds reasonable limit", dwStreams), "")
	}
}

func (p *AVIParser) parseStreamHeader(fi *FormatInfo, data []byte, offset int64, chunkSize int64) {
	if int64(len(data)) < offset+56 {
		return
	}
	fccType := string(data[offset : offset+4])
	fccHandler := string(data[offset+8 : offset+12])
	dwScale := binary.LittleEndian.Uint32(data[offset+20 : offset+24])
	dwRate := binary.LittleEndian.Uint32(data[offset+24 : offset+28])
	dwStart := binary.LittleEndian.Uint32(data[offset+28 : offset+32])
	dwLength := binary.LittleEndian.Uint32(data[offset+32 : offset+36])
	dwSuggestedBufferSize := binary.LittleEndian.Uint32(data[offset+40 : offset+44])
	_ = chunkSize
	if fccType != "vids" && fccType != "auds" && fccType != "txts" && fccType != "mids" {
		fi.AddAnomaly(offset, RiskLow, "Unknown Stream Type",
			fmt.Sprintf("fccType=%q is not a standard type", fccType), "")
	}
	if fccHandler != "" {
		for _, c := range fccHandler {
			if c < 0x20 || c > 0x7e {
				fi.AddAnomaly(offset, RiskMedium, "Non-printable Stream Handler",
					fmt.Sprintf("fccHandler=%q contains invalid characters", fccHandler), "")
				break
			}
		}
	}
	if dwScale == 0 && dwRate > 0 {
		fi.AddAnomaly(offset, RiskMedium, "Zero Stream Scale",
			"dwScale=0 in stream header (potential division by zero)", "")
	}
	if dwSuggestedBufferSize > 1<<28 {
		fi.AddAnomaly(offset, RiskMedium, "Excessive Buffer Size",
			fmt.Sprintf("dwSuggestedBufferSize=%d > 256MB", dwSuggestedBufferSize),
			"CVE-2020-22015")
	}
	if dwLength > 1<<24 && dwRate > 0 {
		fi.AddAnomaly(offset, RiskLow, "Very Long Stream",
			fmt.Sprintf("stream length=%d frames", dwLength), "")
	}
	if dwStart > 0 && dwStart < 100 {
		_ = dwStart
	}
}

func (p *AVIParser) parseIndex(fi *FormatInfo, data []byte, offset int64, size int64) {
	if size < 16 {
		return
	}
	entrySize := int64(16)
	count := size / entrySize
	if count > 1<<24 {
		fi.AddAnomaly(offset, RiskMedium, "Excessive Index Entries",
			fmt.Sprintf("idx1 has %d entries", count), "")
		return
	}
	for i := int64(0); i < count && i < 100; i++ {
		entryOff := offset + i*entrySize
		if entryOff+16 > int64(len(data)) {
			break
		}
		dwFlags := binary.LittleEndian.Uint32(data[entryOff+8 : entryOff+12])
		dwOffset := binary.LittleEndian.Uint32(data[entryOff+12 : entryOff+16])
		if dwFlags&^0x13 != 0 {
			fi.AddAnomaly(offset+i*entrySize, RiskLow, "Unknown Index Flags",
				fmt.Sprintf("idx1 entry %d flags=0x%x", i, dwFlags), "")
		}
		if dwOffset > uint32(len(data)) {
			fi.AddAnomaly(offset+i*entrySize, RiskHigh, "Index Entry Beyond File",
				fmt.Sprintf("idx1 entry %d offset=%d > file size", i, dwOffset),
				"CVE-2020-22033")
		}
	}
}

func (p *AVIParser) parseStreamFormat(fi *FormatInfo, data []byte, offset int64, chunkSize int64) {
	if int64(len(data)) < offset+16 {
		return
	}
	biSize := binary.LittleEndian.Uint32(data[offset : offset+4])
	_ = biSize
	if chunkSize >= 44 {
		biCompression := string(data[offset+16 : offset+20])
		isPrintable := true
		for _, c := range biCompression {
			if c < 0x20 || c > 0x7e {
				isPrintable = false
				break
			}
		}
		if isPrintable && biCompression != "\x00\x00\x00\x00" {
			fi.AddCodec(biCompression)
			if fi.Codec == "" {
				fi.Codec = biCompression
			}
		}
	}
	if chunkSize >= 18 {
		wFormatTag := binary.LittleEndian.Uint16(data[offset+16 : offset+18])
		_ = wFormatTag
	}
	extradataOff := int64(biSize)
	if extradataOff < chunkSize && extradataOff > 0 {
		extraSize := chunkSize - extradataOff
		if extraSize > 0 && extraSize <= 1<<18 {
			fi.CodecExtradata = data[offset+extradataOff : offset+extradataOff+extraSize]
		}
	}
}
