package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigil/vigil/internal/assess"
	"github.com/vigil/vigil/internal/format"
	"github.com/vigil/vigil/internal/probe"
	"github.com/vigil/vigil/internal/sanitize"
	"github.com/vigil/vigil/internal/signatures"
)

const appVer = "0.1.0"

type Config struct {
	Clean      bool
	DryRun     bool
	Force      bool
	Recursive  bool
	OutputDir  string
	Suffix     string
	JSON       bool
	Verbose    bool
	ListSigs   bool
	Args       []string
}

func buildBanner() string {
	return fmt.Sprintf(`╔══════════════════════════════════════╗
║       Vigil v%s                    ║
║   Video Vulnerability Pre-Checker   ║
║   Silent. Safe. Symmetric Cleanup.  ║
╚══════════════════════════════════════╝`, appVer)
}

func main() {
	cfg := parseFlags()
	if cfg.ListSigs {
		fmt.Println(buildBanner())
		fmt.Println()
		fmt.Println("Known Vulnerability Signatures:")
		fmt.Println(signatures.FormatSignaturesTable())
		return
	}
	if len(cfg.Args) == 0 {
		fmt.Println(buildBanner())
		fmt.Println()
		fmt.Println("Usage: vigil [options] <path> [path...]")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  vigil scan video.mp4")
		fmt.Println("  vigil scan --clean video.mp4")
		fmt.Println("  vigil scan --recursive ./videos/")
		fmt.Println("  vigil signatures")
		return
	}
	fmt.Println(buildBanner())
	fmt.Println()
	for _, arg := range cfg.Args {
		info, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error accessing %s: %v\n", arg, err)
			continue
		}
		if info.IsDir() {
			scanDir(arg, cfg)
		} else {
			scanFile(arg, cfg)
		}
	}
}

func parseFlags() Config {
	var cfg Config
	flag.BoolVar(&cfg.Clean, "clean", false, "Sanitize detected threats (symmetric cleanup)")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "Show what would be cleaned without modifying")
	flag.BoolVar(&cfg.Force, "force", false, "Overwrite input file with cleaned version")
	flag.BoolVar(&cfg.Recursive, "recursive", false, "Scan directories recursively")
	flag.BoolVar(&cfg.Recursive, "r", false, "Scan directories recursively (shorthand)")
	flag.BoolVar(&cfg.JSON, "json", false, "Output as JSON")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output (shorthand)")
	flag.BoolVar(&cfg.ListSigs, "signatures", false, "List known FFmpeg vulnerability signatures")
	flag.StringVar(&cfg.OutputDir, "outdir", "", "Output directory for cleaned files")
	flag.StringVar(&cfg.Suffix, "suffix", "_clean", "Suffix for cleaned files")
	flag.Parse()
	cfg.Args = flag.Args()
	scanCmd := false
	if len(cfg.Args) > 0 && cfg.Args[0] == "scan" {
		scanCmd = true
		cfg.Args = cfg.Args[1:]
	}
	if !scanCmd && !cfg.ListSigs && len(cfg.Args) > 0 && cfg.Args[0] == "signatures" {
		cfg.ListSigs = true
		cfg.Args = nil
	}
	return cfg
}

func scanDir(dir string, cfg Config) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error reading directory %s: %v\n", dir, err)
		return
	}
	videoExts := map[string]bool{
		".mp4": true, ".mov": true, ".m4v": true, ".3gp": true, ".3g2": true,
		".avi": true, ".mkv": true, ".webm": true, ".mka": true, ".mks": true,
		".wmv": true, ".flv": true, ".f4v": true, ".mpg": true, ".mpeg": true,
		".ts":  true, ".m2ts": true, ".divx": true, ".xvid": true, ".ogv": true,
		".rm":  true, ".rmvb": true, ".asf": true, ".vob": true,
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if cfg.Recursive {
				scanDir(path, cfg)
			}
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if !videoExts[ext] {
			continue
		}
		scanFile(path, cfg)
	}
}

func scanFile(path string, cfg Config) {
	sf, err := probe.OpenSafe(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s: %v\n", path, err)
		return
	}
	sf.Close()
	fi, err := probe.ProbeFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s: %v\n", path, err)
		return
	}
	fmt.Printf("📄 Scanning: %s\n", path)
	header := fi.Header
	fmtType := format.DetectFormat(header)
	if fmtType == format.FormatUnknown {
		fmt.Printf("   ⚠ Unrecognized video format\n")
		return
	}
	info := &format.FormatInfo{
		Type: fmtType,
		Size: fi.Size,
	}
	var parser format.Parser
	switch fmtType {
	case format.FormatMP4, format.FormatMOV:
		parser = &format.MP4Parser{}
	case format.FormatAVI:
		parser = &format.AVIParser{}
	case format.FormatMKV:
		parser = &format.MKVParser{}
	default:
		fmt.Printf("   ⚠ No parser available for %s\n", fmtType)
		return
	}
	err = parser.Parse(info, header)
	if err != nil {
		fmt.Printf("   ⚠ Parse warning: %v\n", err)
	}
	if cfg.Verbose && len(info.RawBoxes) > 0 {
		fmt.Print("   Box tree (" + fmtType.String() + "):\n")
		for _, b := range info.RawBoxes {
			indent := ""
			for i := 0; i < b.Depth; i++ {
				indent += "  "
			}
			fmt.Printf("     %s[%s] @%d sz=%d\n", indent, b.Type, b.Offset, b.Size)
		}
	}
	report := assess.Assess(info, path, fi.Size)
	if cfg.JSON {
		fmt.Println(report.JSON())
	} else {
		fmt.Println(report.String())
	}
	if cfg.Clean || cfg.DryRun {
		sanCfg := sanitize.DefaultConfig()
		sanCfg.DryRun = cfg.DryRun
		sanCfg.Force = cfg.Force
		sanCfg.OutDir = cfg.OutputDir
		sanCfg.Suffix = cfg.Suffix
		if cfg.Verbose {
			sanCfg.Options = append(sanCfg.Options, sanitize.OptRemoveUDTA, sanitize.OptStripMetadata)
		}
		result, err := sanitize.Sanitize(report, sanCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   ❌ Sanitize error: %v\n", err)
			return
		}
		if cfg.DryRun {
			fmt.Println("   🔍 Dry-run: Would perform symmetric cleanup:")
			for _, r := range result.StrippedRisks {
				fmt.Printf("     • %s\n", r)
			}
			if len(result.StrippedRisks) == 0 {
				fmt.Println("     (no cleanup needed)")
			}
		} else {
			sizeSaved := result.InputSize - result.OutputSize
			fmt.Printf("   ✅ Symmetric cleanup complete:\n")
			fmt.Printf("      Output: %s\n", result.OutputPath)
			fmt.Printf("      Stripped: %d risk(s)\n", result.StrippedCount)
			fmt.Printf("      Size: %s → %s (saved %s)\n",
				assess.FormatSize(result.InputSize),
				assess.FormatSize(result.OutputSize),
				assess.FormatSize(sizeSaved))
		}
	}
	fmt.Println()
}
