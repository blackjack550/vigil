package format

import (
	"fmt"
	"strings"
)

type FormatType int

const (
	FormatUnknown FormatType = iota
	FormatMP4
	FormatMOV
	FormatAVI
	FormatMKV
	FormatWebM
)

func (f FormatType) String() string {
	switch f {
	case FormatMP4:
		return "MP4"
	case FormatMOV:
		return "MOV"
	case FormatAVI:
		return "AVI"
	case FormatMKV:
		return "MKV"
	case FormatWebM:
		return "WebM"
	default:
		return "Unknown"
	}
}

type RiskLevel int

const (
	RiskNone RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "Low"
	case RiskMedium:
		return "Medium"
	case RiskHigh:
		return "High"
	case RiskCritical:
		return "Critical"
	default:
		return "None"
	}
}

type Anomaly struct {
	Offset      int64
	Severity    RiskLevel
	Category    string
	Description string
	CVE         string
	AffectedVer string
	FixedVer    string
	SafeVer     string
	RCE         bool
	RCEScore    float64
}

type FormatInfo struct {
	Type      FormatType
	Size      int64
	Anomalies []Anomaly

	Width     int
	Height    int
	Duration  float64
	Bitrate   int
	Codec     string
	Streams   int

	VideoCodecFourCC string
	AudioCodecFourCC string
	CodecList        []string
	CodecExtradata   []byte

	HasMoov   bool
	HasMdat   bool
	BoxCount  int

	RawBoxes  []BoxInfo
}

func (fi *FormatInfo) AddCodec(codec string) {
	for _, c := range fi.CodecList {
		if c == codec {
			return
		}
	}
	fi.CodecList = append(fi.CodecList, codec)
	shortCodec := codec
	if len(shortCodec) > 4 {
		if len(shortCodec) >= 7 && shortCodec[:2] == "V_" {
			shortCodec = codec[2:]
		} else if len(shortCodec) >= 7 && shortCodec[:2] == "A_" {
			shortCodec = codec[2:]
		} else if len(shortCodec) >= 7 && shortCodec[:2] == "S_" {
			shortCodec = codec[2:]
		}
	}
	if fi.VideoCodecFourCC == "" {
		for _, v := range videoCodecPrefixes {
			if len(shortCodec) >= len(v) && shortCodec[:len(v)] == v {
				fi.VideoCodecFourCC = shortCodec
				break
			}
		}
		if strings.Contains(shortCodec, "AV1") || strings.Contains(shortCodec, "av01") {
			fi.VideoCodecFourCC = "av01"
		}
		if strings.Contains(shortCodec, "VP90") || strings.Contains(shortCodec, "VP9") {
			if fi.VideoCodecFourCC == "" {
				fi.VideoCodecFourCC = "vp90"
			}
		}
	}
	if fi.AudioCodecFourCC == "" {
		for _, v := range audioCodecPrefixes {
			if len(shortCodec) >= len(v) && shortCodec[:len(v)] == v {
				fi.AudioCodecFourCC = shortCodec
				break
			}
		}
	}
}

var videoCodecPrefixes = []string{
	"avc1", "hvc1", "hev1", "av01", "vp08", "vp09", "vp80", "vp90",
	"mp4v", "xvid", "divx", "wmv", "flv1", "rv", "theo", "vf",
	"jpeg", "mjpg", "png", "apcn", "apch", "dnx", "pro",
	"cfhd", "cvid", "svq", "s263", "h263", "h264", "h265",
	"rasc", "sanm", "dhav", "rv60", "rv40", "rv30", "rv20", "rv10",
}

var audioCodecPrefixes = []string{
	"mp4a", "aac", "mp3", "ac-3", "ec-3", "opus", "vorb",
	"flac", "alac", "pcm", "twos", "sowt", "ima4",
	"als", "dts", "mlpa", "wmav", "spee",
}

type BoxInfo struct {
	Offset   int64
	Size     int64
	Type     string
	Depth    int
}

func DetectFormat(header []byte) FormatType {
	if len(header) >= 4 {
		if header[0] == 0x1a && header[1] == 0x45 && header[2] == 0xdf && header[3] == 0xa3 {
			return FormatMKV
		}
		sig := string(header[:4])
		switch sig {
		case "ftyp":
			return FormatMP4
		case "RIFF":
			if len(header) >= 12 && string(header[8:12]) == "AVI " {
				return FormatAVI
			}
		}
	}
	if len(header) >= 8 && string(header[4:8]) == "ftyp" {
		return FormatMP4
	}
	return FormatUnknown
}

type Parser interface {
	Parse(info *FormatInfo, data []byte) error
}

func (fi *FormatInfo) AddAnomaly(offset int64, severity RiskLevel, category, description, cve string) {
	fi.Anomalies = append(fi.Anomalies, Anomaly{
		Offset:      offset,
		Severity:    severity,
		Category:    category,
		Description: description,
		CVE:         cve,
	})
}

func (fi *FormatInfo) HighestRisk() RiskLevel {
	highest := RiskNone
	for _, a := range fi.Anomalies {
		if a.Severity > highest {
			highest = a.Severity
		}
	}
	return highest
}

func (fi *FormatInfo) Score() float64 {
	if len(fi.Anomalies) == 0 {
		return 0
	}
	weights := map[RiskLevel]float64{
		RiskLow:      1,
		RiskMedium:   3,
		RiskHigh:     6,
		RiskCritical: 9,
	}
	total := 0.0
	for _, a := range fi.Anomalies {
		total += weights[a.Severity]
	}
	score := total / float64(len(fi.Anomalies))
	highCount := 0
	for _, a := range fi.Anomalies {
		if a.Severity >= RiskHigh {
			highCount++
		}
	}
	if highCount > 1 {
		score *= 1.5
	}
	if score > 10 {
		score = 10
	}
	return score
}

func (fi *FormatInfo) Summary() string {
	if len(fi.Anomalies) == 0 {
		return fmt.Sprintf("[%s] Clean - no anomalies detected", fi.Type)
	}
	return fmt.Sprintf("[%s] %d anomalies (highest: %s, score: %.1f/10)",
		fi.Type, len(fi.Anomalies), fi.HighestRisk(), fi.Score())
}
