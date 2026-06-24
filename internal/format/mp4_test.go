package format

import (
	"encoding/binary"
	"testing"
)

func makeMP4Box(boxType string, payload []byte) []byte {
	size := 8 + len(payload)
	b := make([]byte, size)
	binary.BigEndian.PutUint32(b[0:4], uint32(size))
	copy(b[4:8], boxType)
	copy(b[8:], payload)
	return b
}

func makeMP4Header() []byte {
	ftypPayload := []byte("isom\x00\x00\x02\x00isomiso2avc1mp41")
	return makeMP4Box("ftyp", ftypPayload)
}

func makeMoovBox() []byte {
	mvhd := makeMP4Box("mvhd", []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00,
	})
	mdat := makeMP4Box("mdat", []byte("this is fake media data"))
	return append(mvhd, mdat...)
}

func TestDetectFormat_MP4(t *testing.T) {
	hdr := makeMP4Header()
	ft := DetectFormat(hdr)
	if ft != FormatMP4 {
		t.Errorf("expected MP4, got %s", ft)
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	ft := DetectFormat([]byte("not a video file"))
	if ft != FormatUnknown {
		t.Errorf("expected Unknown, got %s", ft)
	}
}

func TestMP4Parser_Legitimate(t *testing.T) {
	data := append(makeMP4Header(), makeMoovBox()...)
	fi := &FormatInfo{Type: FormatMP4, Size: int64(len(data))}
	parser := &MP4Parser{}
	err := parser.Parse(fi, data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(fi.Anomalies) > 0 {
		t.Errorf("expected no anomalies for legitimate MP4, got %d: %v", len(fi.Anomalies), fi.Anomalies)
	}
}

func TestMP4Parser_BoxSizeUnderflow(t *testing.T) {
	data := makeMP4Header()
	badBox := []byte{0x00, 0x00, 0x00, 0x03, 'b', 'a', 'd', 'd'}
	data = append(data, badBox...)
	fi := &FormatInfo{Type: FormatMP4, Size: int64(len(data))}
	parser := &MP4Parser{}
	parser.Parse(fi, data)
	found := false
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2023-49528" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CVE-2023-49528 anomaly for box size underflow")
	}
}

func TestMP4Parser_TrunNegativeOffset(t *testing.T) {
	trunPayload := make([]byte, 16)
	binary.BigEndian.PutUint32(trunPayload[0:4], 0x00040000)
	binary.BigEndian.PutUint32(trunPayload[4:8], 5)
	binary.BigEndian.PutUint32(trunPayload[8:12], 0xFFFFFFFF)
	binary.BigEndian.PutUint32(trunPayload[12:16], 100)
	trunBox := makeMP4Box("trun", trunPayload)
	data := append(makeMP4Header(), trunBox...)
	fi := &FormatInfo{Type: FormatMP4, Size: int64(len(data))}
	parser := &MP4Parser{}
	parser.Parse(fi, data)
	found := false
	for _, a := range fi.Anomalies {
		if a.Category == "Negative trun data_offset" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected negative trun data_offset anomaly")
	}
}

func TestAVIParser_Legitimate(t *testing.T) {
	data := make([]byte, 12)
	copy(data[0:4], "RIFF")
	binary.LittleEndian.PutUint32(data[4:8], 0)
	copy(data[8:12], "AVI ")
	avihPayload := make([]byte, 56)
	binary.LittleEndian.PutUint32(avihPayload[0:4], 40000)
	binary.LittleEndian.PutUint32(avihPayload[4:8], 1000000)
	binary.LittleEndian.PutUint32(avihPayload[16:20], 100)
	binary.LittleEndian.PutUint32(avihPayload[24:28], 1)
	binary.LittleEndian.PutUint32(avihPayload[40:44], 640)
	binary.LittleEndian.PutUint32(avihPayload[44:48], 480)
	avihSize := uint32(56)
	avihChunk := make([]byte, 8+56)
	copy(avihChunk[0:4], "avih")
	binary.LittleEndian.PutUint32(avihChunk[4:8], avihSize)
	copy(avihChunk[8:], avihPayload)
	listHdrl := make([]byte, 12+len(avihChunk))
	copy(listHdrl[0:4], "LIST")
	listSize := uint32(4 + len(avihChunk))
	binary.LittleEndian.PutUint32(listHdrl[4:8], listSize)
	copy(listHdrl[8:12], "hdrl")
	copy(listHdrl[12:], avihChunk)
	data = append(data, listHdrl...)
	fi := &FormatInfo{Type: FormatAVI, Size: int64(len(data))}
	parser := &AVIParser{}
	err := parser.Parse(fi, data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	for _, a := range fi.Anomalies {
		if a.Severity >= RiskHigh {
			t.Errorf("unexpected high-risk anomaly: %s: %s", a.Category, a.Description)
		}
	}
}

func TestMKVParser_Detect(t *testing.T) {
	data := []byte{
		0x1a, 0x45, 0xdf, 0xa3, 0x93, 0x42, 0x82, 0x88,
		0x6d, 0x61, 0x74, 0x72, 0x6f, 0x73, 0x6b, 0x61,
		0x87, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	ft := DetectFormat(data)
	if ft != FormatMKV {
		t.Errorf("expected MKV, got %s", ft)
	}
}

func TestFormatInfo_Score(t *testing.T) {
	fi := &FormatInfo{Type: FormatMP4}
	if fi.Score() != 0 {
		t.Errorf("expected score 0 for clean file, got %.1f", fi.Score())
	}
	fi.AddAnomaly(0, RiskLow, "test", "low risk anomaly", "")
	if fi.Score() <= 0 {
		t.Errorf("expected positive score for anomalous file")
	}
}

func TestFormatInfo_HighestRisk(t *testing.T) {
	fi := &FormatInfo{Type: FormatMKV}
	fi.AddAnomaly(0, RiskLow, "a", "low", "")
	fi.AddAnomaly(0, RiskHigh, "b", "high", "")
	if fi.HighestRisk() != RiskHigh {
		t.Errorf("expected Highest=High, got %s", fi.HighestRisk())
	}
}
