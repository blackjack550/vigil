package version

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type FFmpegVersion struct {
	Raw    string
	Major  int
	Minor  int
	Patch  int
	GitSHA string
	Valid  bool
}

func (v *FFmpegVersion) String() string {
	if !v.Valid {
		return "unknown"
	}
	return v.Raw
}

func (v *FFmpegVersion) AtLeast(major, minor, patch int) bool {
	if !v.Valid {
		return false
	}
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Patch >= patch
}

func (v *FFmpegVersion) Below(major, minor, patch int) bool {
	if !v.Valid {
		return false
	}
	return !v.AtLeast(major, minor, patch)
}

func (v *FFmpegVersion) Between(minMajor, minMinor, minPatch, maxMajor, maxMinor, maxPatch int) bool {
	return v.AtLeast(minMajor, minMinor, minPatch) && v.Below(maxMajor, maxMinor, maxPatch)
}

func Parse(raw string) *FFmpegVersion {
	v := &FFmpegVersion{Raw: strings.TrimSpace(raw), Valid: false}
	re := regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
	matches := re.FindStringSubmatch(v.Raw)
	if len(matches) < 3 {
		return v
	}
	v.Major, _ = strconv.Atoi(matches[1])
	v.Minor, _ = strconv.Atoi(matches[2])
	if matches[3] != "" {
		v.Patch, _ = strconv.Atoi(matches[3])
	}
	v.Valid = true
	if idx := strings.Index(v.Raw, "git"); idx >= 0 {
		v.GitSHA = strings.TrimSpace(v.Raw[idx+3:])
	}
	return v
}

func DetectLocal() *FFmpegVersion {
	cmd := exec.Command("ffmpeg", "-version")
	output, err := cmd.Output()
	if err != nil {
		return &FFmpegVersion{Raw: "", Valid: false}
	}
	firstLine := strings.SplitN(string(output), "\n", 2)[0]
	return Parse(firstLine)
}

type VersionExpr struct {
	Raw          string
	MinMajor     int
	MinMinor     int
	MinPatch     int
	MaxMajor     int
	MaxMinor     int
	MaxPatch     int
	HasMin       bool
	HasMax       bool
	HasRange     bool
}

func ParseExpr(expr string) (*VersionExpr, error) {
	ve := &VersionExpr{Raw: expr}
	expr = strings.TrimSpace(expr)
	if expr == "*" || expr == "" {
		return ve, nil
	}
	re := regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
	if strings.Contains(expr, "-") {
		parts := strings.SplitN(expr, "-", 2)
		if len(parts) == 2 {
			if m := re.FindStringSubmatch(parts[0]); len(m) >= 3 {
				ve.MinMajor, _ = strconv.Atoi(m[1])
				ve.MinMinor, _ = strconv.Atoi(m[2])
				if m[3] != "" {
					ve.MinPatch, _ = strconv.Atoi(m[3])
				}
				ve.HasMin = true
			}
			if m := re.FindStringSubmatch(parts[1]); len(m) >= 3 {
				ve.MaxMajor, _ = strconv.Atoi(m[1])
				ve.MaxMinor, _ = strconv.Atoi(m[2])
				if m[3] != "" {
					ve.MaxPatch, _ = strconv.Atoi(m[3])
				}
				ve.HasMax = true
			}
			ve.HasRange = true
			return ve, nil
		}
	}
	if strings.HasPrefix(expr, "<=") {
		if m := re.FindStringSubmatch(expr[2:]); len(m) >= 3 {
			ve.MaxMajor, _ = strconv.Atoi(m[1])
			ve.MaxMinor, _ = strconv.Atoi(m[2])
			if m[3] != "" {
				ve.MaxPatch, _ = strconv.Atoi(m[3])
			}
			ve.HasMax = true
			return ve, nil
		}
	}
	if strings.HasPrefix(expr, "<") {
		if m := re.FindStringSubmatch(expr[1:]); len(m) >= 3 {
			ve.MaxMajor, _ = strconv.Atoi(m[1])
			ve.MaxMinor, _ = strconv.Atoi(m[2])
			if m[3] != "" {
				ve.MaxPatch, _ = strconv.Atoi(m[3])
			}
			ve.HasMax = true
			return ve, nil
		}
	}
	if strings.HasPrefix(expr, ">=") {
		if m := re.FindStringSubmatch(expr[2:]); len(m) >= 3 {
			ve.MinMajor, _ = strconv.Atoi(m[1])
			ve.MinMinor, _ = strconv.Atoi(m[2])
			if m[3] != "" {
				ve.MinPatch, _ = strconv.Atoi(m[3])
			}
			ve.HasMin = true
			return ve, nil
		}
	}
	if m := re.FindStringSubmatch(expr); len(m) >= 3 {
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		patch := 0
		if m[3] != "" {
			patch, _ = strconv.Atoi(m[3])
		}
		ve.HasMax = true
		ve.MaxMajor = major
		ve.MaxMinor = minor
		ve.MaxPatch = patch
		if !strings.HasPrefix(expr, "=") {
			ve.HasMin = true
			ve.MinMajor = major
			ve.MinMinor = minor
			ve.MinPatch = patch
		}
		return ve, nil
	}
	return ve, fmt.Errorf("cannot parse version expression: %s", expr)
}

func (ve *VersionExpr) Matches(v *FFmpegVersion) bool {
	if !v.Valid {
		return true
	}
	if ve.HasMin {
		if v.Major < ve.MinMajor ||
			(v.Major == ve.MinMajor && v.Minor < ve.MinMinor) ||
			(v.Major == ve.MinMajor && v.Minor == ve.MinMinor && v.Patch < ve.MinPatch) {
			return false
		}
	}
	if ve.HasMax {
		if v.Major > ve.MaxMajor ||
			(v.Major == ve.MaxMajor && v.Minor > ve.MaxMinor) ||
			(v.Major == ve.MaxMajor && v.Minor == ve.MaxMinor && v.Patch >= ve.MaxPatch) {
			return false
		}
	}
	return true
}
