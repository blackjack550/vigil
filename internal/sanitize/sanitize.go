package sanitize

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigil/vigil/internal/assess"
	"github.com/vigil/vigil/internal/format"
	"github.com/vigil/vigil/internal/probe"
)

type SanitizeResult struct {
	InputPath      string
	OutputPath     string
	InputSize      int64
	OutputSize     int64
	StrippedCount  int
	StrippedRisks  []string
	Error          error
}

type SanitizeOption int

const (
	OptCopySafeOnly SanitizeOption = iota
	OptRemoveJUNK
	OptRemoveUDTA
	OptRemoveUnknownBoxes
	OptStripMetadata
	OptStripAllNonEssential
	OptVerbose
)

type SanitizeConfig struct {
	Options []SanitizeOption
	DryRun  bool
	Force   bool
	OutDir  string
	Suffix  string
}

func DefaultConfig() SanitizeConfig {
	return SanitizeConfig{
		Options: []SanitizeOption{OptRemoveJUNK, OptRemoveUnknownBoxes},
		Suffix:  "_clean",
	}
}

func Sanitize(report *assess.Report, config SanitizeConfig) (*SanitizeResult, error) {
	if report.Safe {
		return &SanitizeResult{
			InputPath:  report.FilePath,
			OutputSize: report.FileSize,
			OutputPath: report.FilePath,
		}, nil
	}
	ext := filepath.Ext(report.FilePath)
	base := strings.TrimSuffix(filepath.Base(report.FilePath), ext)
	outDir := config.OutDir
	if outDir == "" {
		outDir = filepath.Dir(report.FilePath)
	}
	outName := fmt.Sprintf("%s%s%s", base, config.Suffix, ext)
	outPath := filepath.Join(outDir, outName)
	if report.FilePath == outPath {
		if !config.Force {
			return nil, fmt.Errorf("sanitize: output path same as input (use --force to overwrite or set a different suffix)")
		}
	}
	sf, err := probe.OpenSafe(report.FilePath)
	if err != nil {
		return nil, fmt.Errorf("sanitize: open input: %w", err)
	}
	defer sf.Close()
	outFile, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("sanitize: create output: %w", err)
	}
	defer outFile.Close()
	result := &SanitizeResult{
		InputPath:  report.FilePath,
		OutputPath: outPath,
		InputSize:  report.FileSize,
	}
	hasAnomalies := false
	for _, a := range report.Anomalies {
		if a.Severity >= format.RiskMedium {
			hasAnomalies = true
			break
		}
	}
	if !hasAnomalies {
		result.StrippedCount = 0
		result.OutputSize = report.FileSize
		_, err := sf.File.Seek(0, 0)
		if err != nil {
			return nil, fmt.Errorf("sanitize: seek: %w", err)
		}
		_, err = outFile.ReadFrom(sf.File)
		if err != nil {
			return nil, fmt.Errorf("sanitize: copy: %w", err)
		}
		return result, nil
	}
	stripList := p.buildStripList(&report.FormatInfo, config)
	if len(stripList) == 0 {
		result.OutputSize = report.FileSize
		_, err := sf.File.Seek(0, 0)
		if err != nil {
			return nil, fmt.Errorf("sanitize: seek: %w", err)
		}
		_, err = outFile.ReadFrom(sf.File)
		if err != nil {
			return nil, fmt.Errorf("sanitize: copy: %w", err)
		}
		return result, nil
	}
	if config.DryRun {
		result.StrippedCount = len(stripList)
		for _, s := range stripList {
			result.StrippedRisks = append(result.StrippedRisks, fmt.Sprintf("Would strip %s @%d-%d (%s)", s.BoxType, s.Offset, s.Offset+s.Size, s.Reason))
		}
		return result, nil
	}
	written, err := p.copySkipping(sf.File, outFile, stripList)
	if err != nil {
		return nil, fmt.Errorf("sanitize: copy with skip: %w", err)
	}
	result.OutputSize = written
	result.StrippedCount = len(stripList)
	for _, s := range stripList {
		result.StrippedRisks = append(result.StrippedRisks, fmt.Sprintf("Stripped %s @%d-%d (%s)", s.BoxType, s.Offset, s.Offset+s.Size, s.Reason))
	}
	return result, nil
}

type stripEntry struct {
	Offset  int64
	Size    int64
	BoxType string
	Reason  string
}

func (p *sanitizer) buildStripList(fi *format.FormatInfo, config SanitizeConfig) []stripEntry {
	var strips []stripEntry
	hasOpt := func(opt SanitizeOption) bool {
		for _, o := range config.Options {
			if o == opt {
				return true
			}
		}
		return false
	}
	if hasOpt(OptRemoveJUNK) {
		for _, b := range fi.RawBoxes {
			if b.Type == "JUNK" || b.Type == "FREE" {
				if b.Size < 8 {
					continue
				}
				reason := fmt.Sprintf("non-essential %s box", b.Type)
				strips = append(strips, stripEntry{Offset: b.Offset, Size: b.Size, BoxType: b.Type, Reason: reason})
			}
		}
	}
	if hasOpt(OptRemoveUDTA) {
		for _, b := range fi.RawBoxes {
			if b.Type == "udta" || b.Type == "meta" {
				if b.Size < 8 {
					continue
				}
				reason := fmt.Sprintf("user data %s box (potential metadata exploit vector)", b.Type)
				strips = append(strips, stripEntry{Offset: b.Offset, Size: b.Size, BoxType: b.Type, Reason: reason})
			}
		}
	}
	if hasOpt(OptRemoveUnknownBoxes) {
		knownBoxes := map[string]bool{
			"ftyp": true, "moov": true, "trak": true, "mdia": true,
			"minf": true, "stbl": true, "stsd": true, "stts": true,
			"stsc": true, "stsz": true, "stco": true, "stss": true,
			"mdat": true, "free": true, "skip": true, "edts": true,
			"elst": true, "hdlr": true, "dref": true, "vmhd": true,
			"smhd": true, "hmhd": true, "nmhd": true, "dinf": true,
			"avc1": true, "avcC": true, "mp4a": true, "esds": true,
			"wave": true, "mvhd": true, "tkhd": true, "mdhd": true,
			"url":  true, "urn":  true, "ctts": true, "co64": true,
			"cprt": true, "sdtp": true, "sbgp": true, "sgpd": true,
			"saio": true, "saiz": true, "pssh": true, "senc": true,
			"moof": true, "traf": true, "trun": true, "tfhd": true,
			"tfdt": true, "mvex": true, "mehd": true, "trex": true,
		}
		for _, b := range fi.RawBoxes {
			if len(b.Type) != 4 {
				continue
			}
			isPrintable := true
			for _, c := range b.Type {
				if c < 0x20 || c > 0x7e {
					isPrintable = false
					break
				}
			}
			if !isPrintable {
				reason := fmt.Sprintf("non-printable box type %q (likely exploit payload)", b.Type)
				strips = append(strips, stripEntry{Offset: b.Offset, Size: b.Size, BoxType: b.Type, Reason: reason})
				continue
			}
			if !knownBoxes[b.Type] {
				reason := fmt.Sprintf("unknown box type %q (potential exploit vector)", b.Type)
				strips = append(strips, stripEntry{Offset: b.Offset, Size: b.Size, BoxType: b.Type, Reason: reason})
			}
		}
	}
	if hasOpt(OptStripMetadata) {
		for _, b := range fi.RawBoxes {
			if b.Type == "udta" || b.Type == "meta" || b.Type == "cprt" || b.Type == "ilst" {
				if b.Size >= 8 {
					reason := fmt.Sprintf("metadata %s box stripped", b.Type)
					strips = append(strips, stripEntry{Offset: b.Offset, Size: b.Size, BoxType: b.Type, Reason: reason})
				}
			}
		}
	}
	strips = dedupeStrips(strips)
	return strips
}

func dedupeStrips(strips []stripEntry) []stripEntry {
	covered := make(map[int64]bool)
	var result []stripEntry
	for _, s := range strips {
		if covered[s.Offset] {
			continue
		}
		result = append(result, s)
		covered[s.Offset] = true
	}
	return result
}

type sanitizer struct{}

var p = &sanitizer{}

func (s *sanitizer) copySkipping(inFile *os.File, outFile *os.File, skips []stripEntry) (int64, error) {
	info, err := inFile.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}
	fileSize := info.Size()
	skipMap := make(map[int64]int64)
	for _, sk := range skips {
		if sk.Offset >= 0 && sk.Size > 0 && sk.Offset+sk.Size <= fileSize {
			skipMap[sk.Offset] = sk.Size
		}
	}
	if len(skipMap) == 0 {
		n, err := outFile.ReadFrom(inFile)
		return n, err
	}
	var totalWritten int64
	pos := int64(0)
	for pos < fileSize {
		if size, skip := skipMap[pos]; skip {
			pos += size
			continue
		}
		nextSkip := fileSize
		for skipPos := range skipMap {
			if skipPos > pos && skipPos < nextSkip {
				nextSkip = skipPos
			}
		}
		readSize := nextSkip - pos
		if readSize <= 0 {
			readSize = fileSize - pos
		}
		if readSize > probe.ChunkMaxSize {
			readSize = probe.ChunkMaxSize
		}
		buf := make([]byte, readSize)
		n, err := inFile.ReadAt(buf, pos)
		if n > 0 {
			wn, werr := outFile.Write(buf[:n])
			totalWritten += int64(wn)
			if werr != nil {
				return totalWritten, fmt.Errorf("write: %w", werr)
			}
		}
		if err != nil {
			return totalWritten, nil
		}
		pos += int64(n)
	}
	return totalWritten, nil
}
