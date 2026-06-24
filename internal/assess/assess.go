package assess

import (
	"fmt"
	"strings"

	"github.com/vigil/vigil/internal/format"
	"github.com/vigil/vigil/internal/signatures"
)

type Report struct {
	FilePath   string
	FileSize   int64
	Format     format.FormatType
	FormatInfo format.FormatInfo
	Anomalies  []format.Anomaly
	TotalScore float64
	RiskLevel  format.RiskLevel
	Summary    string
	Safe       bool
}

func Assess(fi *format.FormatInfo, path string, fileSize int64) *Report {
	sigAnomalies := signatures.RunSignatureChecks(fi)
	anomalySet := make(map[string]bool)
	for _, a := range fi.Anomalies {
		key := a.CVE + "|" + a.Category + "|" + a.Description
		anomalySet[key] = true
	}
	var allAnomalies []format.Anomaly
	allAnomalies = append(allAnomalies, fi.Anomalies...)
	for _, a := range sigAnomalies {
		key := a.CVE + "|" + a.Category + "|" + a.Description
		if !anomalySet[key] {
			allAnomalies = append(allAnomalies, a)
			anomalySet[key] = true
		}
	}
	fi.Anomalies = allAnomalies
	score := fi.Score()
	risk := fi.HighestRisk()
	safe := len(allAnomalies) == 0
	summary := fi.Summary()
	if !safe {
		summary = fmt.Sprintf("[%s] %d anomaly(es) | Score: %.1f/10 | Highest Risk: %s",
			fi.Type, len(allAnomalies), score, risk)
	}
	return &Report{
		FilePath:   path,
		FileSize:   fileSize,
		Format:     fi.Type,
		FormatInfo: *fi,
		Anomalies:  allAnomalies,
		TotalScore: score,
		RiskLevel:  risk,
		Summary:    summary,
		Safe:       safe,
	}
}

func (r *Report) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("File:     %s\n", r.FilePath))
		b.WriteString(fmt.Sprintf("Size:     %s\n", FormatSize(r.FileSize)))
	b.WriteString(fmt.Sprintf("Format:   %s\n", r.Format))
	if r.FormatInfo.Width > 0 && r.FormatInfo.Height > 0 {
		b.WriteString(fmt.Sprintf("Dims:     %dx%d\n", r.FormatInfo.Width, r.FormatInfo.Height))
	}
	if r.FormatInfo.Duration > 0 {
		b.WriteString(fmt.Sprintf("Duration: %.2fs\n", r.FormatInfo.Duration))
	}
	if r.FormatInfo.Codec != "" {
		b.WriteString(fmt.Sprintf("Codec:    %s\n", r.FormatInfo.Codec))
	}
	b.WriteString(fmt.Sprintf("Streams:  %d\n", r.FormatInfo.Streams))
	b.WriteString("─────────────────────────────────────\n")
	if r.Safe {
		b.WriteString("✅ No anomalies detected\n")
	} else {
		b.WriteString(fmt.Sprintf("🔴 Risk Score: %.1f/10 (%s)\n", r.TotalScore, r.RiskLevel))
		b.WriteString(fmt.Sprintf("   %d anomaly(ies) found\n", len(r.Anomalies)))
		b.WriteString("\n")
		for i, a := range r.Anomalies {
			icon := riskIcon(a.Severity)
			cve := ""
			if a.CVE != "" {
				cve = fmt.Sprintf(" [%s]", a.CVE)
			}
			offset := ""
			if a.Offset > 0 {
				offset = fmt.Sprintf(" @0x%x", a.Offset)
			}
			b.WriteString(fmt.Sprintf("%s %s%s%s\n", icon, a.Category, cve, offset))
			b.WriteString(fmt.Sprintf("   %s\n", a.Description))
			if i < len(r.Anomalies)-1 {
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

func riskIcon(level format.RiskLevel) string {
	switch level {
	case format.RiskCritical:
		return "💀"
	case format.RiskHigh:
		return "🔴"
	case format.RiskMedium:
		return "🟡"
	case format.RiskLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func (r *Report) JSON() string {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString(fmt.Sprintf("  \"file\": %q,\n", r.FilePath))
	b.WriteString(fmt.Sprintf("  \"size\": %d,\n", r.FileSize))
	b.WriteString(fmt.Sprintf("  \"format\": %q,\n", r.Format.String()))
	b.WriteString(fmt.Sprintf("  \"score\": %.1f,\n", r.TotalScore))
	b.WriteString(fmt.Sprintf("  \"risk\": %q,\n", r.RiskLevel.String()))
	b.WriteString(fmt.Sprintf("  \"safe\": %v,\n", r.Safe))
	b.WriteString(fmt.Sprintf("  \"anomalies\": %d,\n", len(r.Anomalies)))
	b.WriteString("  \"details\": [\n")
	for i, a := range r.Anomalies {
		comma := ","
		if i == len(r.Anomalies)-1 {
			comma = ""
		}
		b.WriteString(fmt.Sprintf("    {\"offset\":%d,\"severity\":%q,\"category\":%q,\"desc\":%q,\"cve\":%q}%s\n",
			a.Offset, a.Severity.String(), a.Category, a.Description, a.CVE, comma))
	}
	b.WriteString("  ]\n")
	b.WriteString("}\n")
	return b.String()
}

func (r *Report) ShortString() string {
	if r.Safe {
		return fmt.Sprintf("[%s] %s — ✅ Safe", r.Format, r.FilePath)
	}
	return fmt.Sprintf("[%s] %s — ⚠ Score: %.1f/10 Risk: %s (%d anomalies)",
		r.Format, r.FilePath, r.TotalScore, r.RiskLevel, len(r.Anomalies))
}

func FormatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(bytes)/(1024*1024*1024))
}
