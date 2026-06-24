package signatures

import (
	"fmt"
	"strings"

	"github.com/vigil/vigil/internal/format"
)

type Signature struct {
	CVE         string
	Title       string
	Description string
	Severity    format.RiskLevel
	Formats     []format.FormatType
	AffectedVer string
	RefURL      string
	Check       func(fi *format.FormatInfo) []format.Anomaly
}

var Signatures = []Signature{
	{
		CVE:         "CVE-2023-49528",
		Title:       "Buffer overflow in libavformat/mov.c",
		Description: "Buffer overflow in FFmpeg's MOV demuxer via crafted box size that wraps around, leading to undersized buffer allocation and subsequent heap overflow.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV},
		AffectedVer: "<= 6.0",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2023-49528",
		Check:       checkBoxSizeWrap,
	},
	{
		CVE:         "CVE-2022-3341",
		Title:       "Buffer overflow in libavformat",
		Description: "A buffer overflow vulnerability in FFmpeg's demuxer when processing malformed container format headers, allowing arbitrary code execution via crafted media files.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "<= 5.1.2",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2022-3341",
		Check:       checkGenericSizeAnomaly,
	},
	{
		CVE:         "CVE-2021-38171",
		Title:       "OOB read in libavformat/mov.c",
		Description: "Out-of-bounds read in the MOV/MP4 demuxer when parsing crafted trun boxes with negative data_offset, leading to information disclosure or crash.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV},
		AffectedVer: "<= 4.4.1",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2021-38171",
		Check:       checkTrunAnomaly,
	},
	{
		CVE:         "CVE-2020-22015",
		Title:       "Heap buffer overflow in libavformat/movenc.c",
		Description: "Heap buffer overflow in FFmpeg's MOV/MP4 muxer/demuxer when processing crafted stsz boxes with large sample sizes leading to integer overflow in buffer allocation.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV},
		AffectedVer: "<= 4.3.2",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2020-22015",
		Check:       checkStszAnomaly,
	},
	{
		CVE:         "CVE-2020-22033",
		Title:       "OOB read in libavformat/utils.c",
		Description: "Out-of-bounds read in FFmpeg's format utilities when processing crafted index tables with chunk offsets beyond the file size.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI},
		AffectedVer: "<= 4.3.2",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2020-22033",
		Check:       checkIndexOffsetAnomaly,
	},
	{
		CVE:         "CVE-2021-38291",
		Title:       "OOB read in libavutil/imgutils.c",
		Description: "Out-of-bounds read in FFmpeg's image utilities when processing crafted image dimensions that cause integer overflow in size computation.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatAVI, format.FormatMKV},
		AffectedVer: "<= 4.4.1",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2021-38291",
		Check:       checkImageDimensionOverflow,
	},
	{
		CVE:         "CVE-2021-38114",
		Title:       "Heap buffer overflow in libavcodec/dnxhddec.c",
		Description: "Heap buffer overflow in DNxHD decoder when processing crafted extradata with oversized configuration payload.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV},
		AffectedVer: "<= 4.4.1",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2021-38114",
		Check:       checkCodecExtradata,
	},
	{
		CVE:         "CVE-2023-51794",
		Title:       "OOB read in libavfilter/af_stereowiden.c",
		Description: "Out-of-bounds read in FFmpeg's stereo widen audio filter due to insufficient bounds checking on crafted audio frame parameters.",
		Severity:    format.RiskMedium,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "<= 6.0",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2023-51794",
		Check:       checkAudioAnomaly,
	},
	{
		CVE:         "CVE-2023-47342",
		Title:       "Heap buffer overflow in libavcodec/exr.c",
		Description: "Heap buffer overflow in OpenEXR decoder when processing crafted EXR data with invalid data window dimensions.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatAVI, format.FormatMKV},
		AffectedVer: "<= 6.0",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2023-47342",
		Check:       checkExrAnomaly,
	},
	{
		CVE:         "CVE-2022-3966",
		Title:       "OOB read in libavcodec/cfhdenc.c",
		Description: "Out-of-bounds read in FFmpeg's CineForm HD decoder when processing crafted video parameters with invalid plane dimensions.",
		Severity:    format.RiskMedium,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI},
		AffectedVer: "<= 5.1.2",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2022-3966",
		Check:       checkVideoDimensionAnomaly,
	},
	{
		CVE:         "CVE-2020-22020",
		Title:       "Buffer overflow in libavfilter/vf_framerate.c",
		Description: "Buffer overflow in frame rate conversion filter when processing crafted video frames with extreme dimension ratios.",
		Severity:    format.RiskMedium,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "<= 4.3.2",
		RefURL:      "https://nvd.nist.gov/vuln/detail/CVE-2020-22020",
		Check:       checkDimensionRatioAnomaly,
	},
	{
		CVE:         "CVE-2026-40962",
		Title:       "Integer overflow in libsvtav1 encoding (libavcodec)",
		Description: "Integer overflow and resultant out-of-bounds write in FFmpeg before 8.1 during encoding with libsvtav1, triggered by crafted AV1 codec configuration parameters leading to undersized buffer allocation.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatMKV},
		AffectedVer: "< 8.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2026-40962",
		Check:       check2026Svtav1Overflow,
	},
	{
		CVE:         "CVE-2026-30997",
		Title:       "OOB read in read_global_param() (libavcodec)",
		Description: "Out-of-bounds read in the read_global_param() function in libavcodec when parsing crafted codec-specific global parameters from container headers, leading to information disclosure.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2026-30997",
		Check:       checkCodecParamExtraction,
	},
	{
		CVE:         "CVE-2026-12706",
		Title:       "Use-after-free in RASC video decoder (libavcodec)",
		Description: "Use-after-free vulnerability in FFmpeg's RASC (Raster) video decoder when processing crafted animation frames with invalid sequence references, allowing memory corruption and potential code execution.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2026-12706",
		Check:       checkRascDecoderAnomaly,
	},
	{
		CVE:         "CVE-2026-8461",
		Title:       "OOB write in libavcodec",
		Description: "Out-of-bounds write vulnerability in FFmpeg's libavcodec library when processing crafted media files with invalid sample buffer dimensions, leading to heap corruption.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2026-8461",
		Check:       check2026OobWrite,
	},
	{
		CVE:         "CVE-2026-6385",
		Title:       "Remote exploit vulnerability in FFmpeg",
		Description: "A flaw found in FFmpeg allowing remote attackers to exploit unspecified memory corruption via crafted container format metadata, potentially leading to remote code execution.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 8.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2026-6385",
		Check:       check2026RemoteExploit,
	},
	{
		CVE:         "CVE-2025-59729",
		Title:       "Integer underflow in DHAV file header parsing (libavformat)",
		Description: "When parsing the header for a DHAV file, an integer underflow occurs in size computation, leading to undersized buffer allocation and subsequent heap buffer overflow.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatAVI},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-59729",
		Check:       checkDhavHeaderUnderflow,
	},
	{
		CVE:         "CVE-2025-59730",
		Title:       "OOB read in SANM frame decoding (libavcodec)",
		Description: "When decoding a frame for a SANM file (ANIM v0 variant), the decoded data is not properly bounds-checked against the output plane size, leading to out-of-bounds read/write.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatAVI},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-59730",
		Check:       checkSanmDecoderAnomaly,
	},
	{
		CVE:         "CVE-2025-59731",
		Title:       "OOB write in OpenEXR DWAA/DWAB compression (libavcodec)",
		Description: "When decoding an OpenEXR file that uses DWAA or DWAB compression, the rijndael buffer size is not initialized resulting in an out-of-bounds write on the stack.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-59731",
		Check:       checkExrDWAAAnomaly,
	},
	{
		CVE:         "CVE-2025-59734",
		Title:       "Use-after-free in SANM decoding (libavcodec)",
		Description: "It is possible to cause a use-after-free write in SANM decoding with a crafted ANIM file due to improper frame reference counting in the animation decoder.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatAVI},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-59734",
		Check:       checkSanmDecoderAnomaly,
	},
	{
		CVE:         "CVE-2025-63757",
		Title:       "Integer overflow in yuv2ya16 pixel conversion (libswscale)",
		Description: "Integer overflow vulnerability in the yuv2ya16_X_c_template function in libswscale when processing crafted video frames with extreme dimensions, leading to undersized buffer allocation.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 8.0",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-63757",
		Check:       checkPixelConversionOverflow,
	},
	{
		CVE:         "CVE-2025-69693",
		Title:       "OOB read in RV60 video decoder (libavcodec)",
		Description: "Out-of-bounds read in FFmpeg 8.0 and 8.0.1 RV60 video decoder (libavcodec/rv60dec.c) when processing crafted RV60 frames with invalid slice parameters.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "8.0 - 8.0.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-69693",
		Check:       checkRv60DecoderAnomaly,
	},
	{
		CVE:         "CVE-2025-9951",
		Title:       "Heap-buffer-overflow in JPEG2000 decoder (libavcodec)",
		Description: "A heap-buffer-overflow write exists in jpeg2000dec in FFmpeg when processing crafted JPEG2000 codestreams with invalid decomposition level parameters.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-9951",
		Check:       checkJpeg2000Anomaly,
	},
	{
		CVE:         "CVE-2025-7700",
		Title:       "ALS audio decoder memory corruption (libavcodec)",
		Description: "A flaw in FFmpeg's ALS (MPEG-4 Audio Lossless) audio decoder where it does not properly validate decoded block lengths, leading to out-of-bounds access.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-7700",
		Check:       checkAlsAudioAnomaly,
	},
	{
		CVE:         "CVE-2025-10256",
		Title:       "NULL pointer dereference in Fireq filter (libavfilter)",
		Description: "A NULL pointer dereference in FFmpeg's Fireq audio filter when processing crafted filter graph parameters with missing channel configuration.",
		Severity:    format.RiskMedium,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-10256",
		Check:       checkFilterGraphAnomaly,
	},
	{
		CVE:         "CVE-2025-22920",
		Title:       "Heap buffer overflow in FFmpeg (libavcodec)",
		Description: "A heap buffer overflow vulnerability in FFmpeg before commit 4bf784c, triggered by crafted media with invalid frame allocation sizes causing undersized buffer allocation.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-22920",
		Check:       check2025HeapOverflow,
	},
	{
		CVE:         "CVE-2025-12343",
		Title:       "TensorFlow backend OOB in libavfilter",
		Description: "A flaw in FFmpeg's TensorFlow backend within the libavfilter library, where specially crafted DNN model inputs can trigger out-of-bounds memory access during filter graph execution.",
		Severity:    format.RiskMedium,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "< 7.1",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-12343",
		Check:       checkDnnFilterAnomaly,
	},
	{
		CVE:         "CVE-2025-25473",
		Title:       "Memory corruption in FFmpeg (libavcodec)",
		Description: "Memory corruption vulnerability in FFmpeg git master before commit c08d30, triggered by crafted video frames with invalid reference picture parameters in video decoders.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "git before c08d30",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-25473",
		Check:       checkVideoRefAnomaly,
	},
	{
		CVE:         "CVE-2025-25469",
		Title:       "Memory corruption via memory allocation (libavcodec)",
		Description: "Memory corruption in FFmpeg git-master before commit d5873b due to improper memory allocation tracking when processing crafted media with invalid sample counts.",
		Severity:    format.RiskHigh,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "git before d5873b",
		RefURL:      "https://security-tracker.debian.org/tracker/CVE-2025-25469",
		Check:       checkMemoryAllocAnomaly,
	},
	{
		CVE:         "CODECDETECT",
		Title:       "Vulnerable codec indicator detection",
		Description: "Detects known vulnerable codecs (RASC, AV1/libsvtav1, SANM, RV60, DHAV, JPEG2000, ALS, EXR, DNxHD, etc.) via FourCC/codec ID in container headers and maps them to their associated CVEs for RCE risk assessment.",
		Severity:    format.RiskCritical,
		Formats:     []format.FormatType{format.FormatMP4, format.FormatMOV, format.FormatAVI, format.FormatMKV},
		AffectedVer: "*",
		RefURL:      "",
		Check:       checkVulnerableCodecPresent,
	},
}

func checkBoxSizeWrap(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2023-49528" {
			found = append(found, a)
		}
	}
	if len(found) == 0 {
		for _, b := range fi.RawBoxes {
			if b.Size < 8 && b.Size > 0 {
				found = append(found, format.Anomaly{
					Offset:      b.Offset,
					Severity:    format.RiskHigh,
					Category:    "Box Size Wrap",
					Description: fmt.Sprintf("Box %s at offset %d has size %d < 8, indicating integer wraparound", b.Type, b.Offset, b.Size),
					CVE:         "CVE-2023-49528",
				})
			}
		}
	}
	return found
}

func checkGenericSizeAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2022-3341" || a.Category == "Box Overflow" || a.Category == "Invalid AVI Chunk Size" || a.Category == "Very Large Cluster" {
			found = append(found, a)
		}
	}
	return found
}

func checkTrunAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2021-38171" || a.Category == "Invalid trun Sample Count" || a.Category == "Negative trun data_offset" {
			found = append(found, a)
		}
	}
	return found
}

func checkStszAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2020-22015" || a.Category == "Sample Size Overflow" || a.Category == "Negative Sample Count" {
			found = append(found, a)
		}
	}
	return found
}

func checkIndexOffsetAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2020-22033" || a.Category == "Index Entry Beyond File" || a.Category == "Chunk Offset Truncation" {
			found = append(found, a)
		}
	}
	return found
}

func checkImageDimensionOverflow(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2021-38291" || a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" {
			found = append(found, a)
		}
	}
	if fi.Width > 0 && fi.Height > 0 {
		w := int64(fi.Width)
		h := int64(fi.Height)
		if w*h > 1<<28 {
			desc := fmt.Sprintf("Image dimensions %dx%d = %d pixels, potential overflow risk", fi.Width, fi.Height, w*h)
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "Dimension Overflow Risk",
				Description: desc,
				CVE:         "CVE-2021-38291",
			})
		}
		if (w>>1)*(h>>1) > 1<<26 {
			found = append(found, format.Anomaly{
				Severity:    format.RiskMedium,
				Category:    "Large Bitmap Allocation",
				Description: fmt.Sprintf("Potential excessive memory allocation for %dx%d frame buffer", fi.Width, fi.Height),
				CVE:         "CVE-2021-38291",
			})
		}
	}
	return found
}

func checkCodecExtradata(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.CVE == "CVE-2021-38114" || a.Category == "Suspicious Extradata Size" || a.Category == "Large Codec Configuration" {
			found = append(found, a)
		}
	}
	return found
}

func checkAudioAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Zero Stream Scale" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskMedium,
				Category:    "Audio Processing Risk",
				Description: a.Description,
				CVE:         "CVE-2023-51794",
			})
		}
	}
	return found
}

func checkExrAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" {
			if fi.Width > 65536 || fi.Height > 65536 {
				found = append(found, format.Anomaly{
					Severity:    format.RiskHigh,
					Category:    "EXR Data Window Risk",
					Description: fmt.Sprintf("Dimensions %dx%d exceed typical EXR data window limits", fi.Width, fi.Height),
					CVE:         "CVE-2023-47342",
				})
			}
		}
	}
	return found
}

func checkVideoDimensionAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" {
			desc := fmt.Sprintf("Unusual video dimensions detected: %dx%d", fi.Width, fi.Height)
			found = append(found, format.Anomaly{
				Severity:    format.RiskMedium,
				Category:    "CineForm/Custom Codec Risk",
				Description: desc,
				CVE:         "CVE-2022-3966",
			})
		}
	}
	return found
}

func checkDimensionRatioAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	if fi.Width > 0 && fi.Height > 0 {
		ratio := float64(fi.Width) / float64(fi.Height)
		if ratio > 100 || ratio < 0.01 {
			found = append(found, format.Anomaly{
				Severity:    format.RiskMedium,
				Category:    "Extreme Aspect Ratio",
				Description: fmt.Sprintf("Aspect ratio %d:%d = %.2f is extreme, may trigger buffer overflow in filters", fi.Width, fi.Height, ratio),
				CVE:         "CVE-2020-22020",
			})
		}
		if fi.Width%2 != 0 || fi.Height%2 != 0 {
		}
	}
	return found
}

func check2026Svtav1Overflow(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Extradata Size" || a.Category == "Large Codec Configuration" {
			desc := "Potential AV1/libsvtav1 codec config with oversized/underflow parameters (CVE-2026-40962)"
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "AV1 Codec Integer Overflow",
				Description: desc,
				CVE:         "CVE-2026-40962",
			})
		}
	}
	if fi.Width > 0 && fi.Height > 0 {
		w := int64(fi.Width)
		h := int64(fi.Height)
		if w*h > 1<<28 {
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "AV1 Encode Overflow Risk",
				Description: fmt.Sprintf("%dx%d frame dimensions may trigger integer overflow in libsvtav1 buffer sizing", fi.Width, fi.Height),
				CVE:         "CVE-2026-40962",
			})
		}
	}
	return found
}

func checkCodecParamExtraction(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Extradata Size" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "Codec Global Param Extraction Risk",
				Description: "Oversized codec configuration block may trigger OOB read in read_global_param()",
				CVE:         "CVE-2026-30997",
			})
		}
	}
	if fi.Codec != "" && len(fi.Codec) > 64 {
		found = append(found, format.Anomaly{
			Severity:    format.RiskHigh,
			Category:    "Codec ID Extraction Risk",
			Description: fmt.Sprintf("CodecID length %d exceeds typical maximum, may trigger OOB in parameter extraction", len(fi.Codec)),
			CVE:         "CVE-2026-30997",
		})
	}
	return found
}

func checkRascDecoderAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" || a.Category == "Dimension Overflow Risk" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "RASC Decoder Use-After-Free Risk",
				Description: "Video dimension anomalies in container may indicate crafted RASC animation frames (CVE-2026-12706)",
				CVE:         "CVE-2026-12706",
			})
		}
	}
	if fi.Streams > 64 {
		found = append(found, format.Anomaly{
			Severity:    format.RiskCritical,
			Category:    "RASC Frame Sequence Risk",
			Description: fmt.Sprintf("High track/stream count (%d) may trigger UAF in RASC frame reference handling", fi.Streams),
			CVE:         "CVE-2026-12706",
		})
	}
	return found
}

func check2026OobWrite(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Box Overflow" || a.Category == "Invalid AVI Chunk Size" || a.Category == "Excessive Buffer Size" || a.Category == "Negative Sample Count" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "2026 OOB Write Risk",
				Description: fmt.Sprintf("Anomaly '%s' indicates potential OOB write vector: %s", a.Category, a.Description),
				CVE:         "CVE-2026-8461",
			})
		}
	}
	return found
}

func check2026RemoteExploit(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	highRiskCount := 0
	for _, a := range fi.Anomalies {
		if a.Severity >= format.RiskHigh {
			highRiskCount++
		}
	}
	if highRiskCount >= 3 {
		found = append(found, format.Anomaly{
			Severity:    format.RiskCritical,
			Category:    "Remote Exploit Risk Accumulation",
			Description: fmt.Sprintf("Multiple high-risk anomalies (%d) create potential remote exploit chain", highRiskCount),
			CVE:         "CVE-2026-6385",
		})
	}
	if fi.BoxCount > 1000 {
		found = append(found, format.Anomaly{
			Severity:    format.RiskCritical,
			Category:    "Exploit Complexity Risk",
			Description: fmt.Sprintf("Excessive container structure complexity (%d atoms/boxes) may conceal exploit payload", fi.BoxCount),
			CVE:         "CVE-2026-6385",
		})
	}
	return found
}

func checkDhavHeaderUnderflow(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Box Underflow" || a.Category == "Box Size Wrap" || a.Category == "Invalid AVI Chunk Size" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "DHAV Header Integer Underflow Risk",
				Description: "Container structure size underflow may trigger integer underflow in DHAV header parsing",
				CVE:         "CVE-2025-59729",
			})
		}
	}
	return found
}

func checkSanmDecoderAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" || a.Category == "Dimension Overflow Risk" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "SANM Animation Decoder Risk",
				Description: "Video dimension anomalies may trigger OOB read/UAF in SANM (ANIM) frame decoder",
				CVE:         "CVE-2025-59730",
			})
		}
	}
	if fi.Width > 0 && fi.Height > 0 {
		if fi.Width*fi.Height%8 != 0 {
		}
	}
	return found
}

func checkExrDWAAAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" {
			if fi.Width > 65536 || fi.Height > 65536 {
				found = append(found, format.Anomaly{
					Severity:    format.RiskCritical,
					Category:    "OpenEXR DWAA/DWAB Stack Overflow Risk",
					Description: fmt.Sprintf("Extreme dimensions %dx%d may trigger stack OOB write in EXR rijndael buffer",
						fi.Width, fi.Height),
					CVE: "CVE-2025-59731",
				})
			}
		}
	}
	for _, a := range fi.Anomalies {
		if a.Category == "Large Codec Configuration" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "EXR Compression Block Risk",
				Description: "Large codec configuration block may indicate crafted DWAA/DWAB compression parameters",
				CVE:         "CVE-2025-59731",
			})
		}
	}
	return found
}

func checkPixelConversionOverflow(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Dimension Overflow Risk" || a.Category == "Large Bitmap Allocation" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "Pixel Format Conversion Overflow Risk",
				Description: "Large frame dimensions may trigger integer overflow in yuv2ya16 pixel conversion buffer sizing",
				CVE:         "CVE-2025-63757",
			})
		}
	}
	return found
}

func checkRv60DecoderAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "RV60 Decoder OOB Read Risk",
				Description: fmt.Sprintf("Suspicious dimensions %dx%d may trigger OOB read in RV60 slice parameter parsing",
					fi.Width, fi.Height),
				CVE: "CVE-2025-69693",
			})
		}
	}
	for _, a := range fi.Anomalies {
		if a.Category == "Negative Sample Count" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "RV60 Slice Parameter Risk",
				Description: "Invalid sample count may trigger OOB read in RV60 decoder slice iteration",
				CVE:         "CVE-2025-69693",
			})
		}
	}
	return found
}

func checkJpeg2000Anomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Suspicious Video Width" || a.Category == "Suspicious Video Height" || a.Category == "Dimension Overflow Risk" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "JPEG2000 Decomposition Risk",
				Description: fmt.Sprintf("Dimensions %dx%d may trigger heap OOB write in JPEG2000 decoder decomposition levels",
					fi.Width, fi.Height),
				CVE: "CVE-2025-9951",
			})
		}
	}
	if fi.Width == 0 && fi.Height == 0 && fi.Streams > 0 {
		found = append(found, format.Anomaly{
			Severity:    format.RiskHigh,
			Category:    "JPEG2000 Missing Dimensions",
			Description: "Stream exists but no valid dimensions — potential crafted JPEG2000 codestream",
			CVE:         "CVE-2025-9951",
		})
	}
	return found
}

func checkAlsAudioAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Large Codec Configuration" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "ALS Audio Decoder Block Length Risk",
				Description: "Large extradata may contain crafted ALS block length parameters leading to OOB",
				CVE:         "CVE-2025-7700",
			})
		}
	}
	for _, a := range fi.Anomalies {
		if a.Category == "Zero Stream Scale" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "ALS Audio Sample Rate Risk",
				Description: "Zero stream scale may trigger division-by-zero or OOB in ALS decoder",
				CVE:         "CVE-2025-7700",
			})
		}
	}
	return found
}

func checkFilterGraphAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Large Codec Configuration" || a.Category == "Suspicious Extradata Size" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskMedium,
				Category:    "Fireq/NULL Deref Filter Graph Risk",
				Description: "Overly large codec config may hide crafted filter graph parameters triggering NULL dereference in Fireq",
				CVE:         "CVE-2025-10256",
			})
		}
	}
	return found
}

func check2025HeapOverflow(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Sample Size Overflow" || a.Category == "Excessive Buffer Size" || a.Category == "Chunk Offset Truncation" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "2025 Heap Overflow Risk",
				Description: fmt.Sprintf("Anomaly '%s' indicates potential heap overflow via crafted frame allocation", a.Category),
				CVE:         "CVE-2025-22920",
			})
		}
	}
	if fi.Width > 0 && fi.Height > 0 {
		w := int64(fi.Width)
		h := int64(fi.Height)
		if w*h > 1<<27 {
			found = append(found, format.Anomaly{
				Severity:    format.RiskCritical,
				Category:    "2025 Frame Buffer Overflow Risk",
				Description: fmt.Sprintf("Frame buffer %dx%d = %d pixels may exceed allocation limits",
					fi.Width, fi.Height, w*h),
				CVE: "CVE-2025-22920",
			})
		}
	}
	return found
}

func checkDnnFilterAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Extreme Aspect Ratio" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskMedium,
				Category:    "DNN/TensorFlow Filter OOB Risk",
				Description: "Extreme aspect ratio may trigger OOB in DNN model input tensor processing",
				CVE:         "CVE-2025-12343",
			})
		}
	}
	return found
}

func checkVideoRefAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Negative Sample Count" || a.Category == "Index Entry Beyond File" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "Video Reference Corruption Risk",
				Description: fmt.Sprintf("Invalid sample/chunk count may corrupt reference picture lists in video decoders"),
				CVE:         "CVE-2025-25473",
			})
		}
	}
	return found
}

func checkMemoryAllocAnomaly(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	for _, a := range fi.Anomalies {
		if a.Category == "Box Overflow" || a.Category == "Invalid AVI Chunk Size" || a.Category == "Excessive Chunk Offsets" {
			found = append(found, format.Anomaly{
				Severity:    format.RiskHigh,
				Category:    "Memory Allocation Tracking Risk",
				Description: "Container structural anomaly may corrupt FFmpeg's internal memory allocation tracking",
				CVE:         "CVE-2025-25469",
			})
		}
	}
	return found
}

var VulnerableCodecs = map[string]VulnerableCodecInfo{
	"rasc":    {CVE: "CVE-2026-12706", Name: "RASC (Raster Animation)", Severity: format.RiskCritical, Desc: "Use-after-free in RASC video decoder"},
	"ras":     {CVE: "CVE-2026-12706", Name: "RASC (Raster Animation)", Severity: format.RiskCritical, Desc: "Use-after-free in RASC video decoder"},
	"av01":    {CVE: "CVE-2026-40962", Name: "AV1 (libsvtav1)", Severity: format.RiskCritical, Desc: "Integer overflow in libsvtav1 encoding buffer sizing"},
	"av1":     {CVE: "CVE-2026-40962", Name: "AV1 (libsvtav1)", Severity: format.RiskCritical, Desc: "Integer overflow in libsvtav1 encoding buffer sizing"},
	"sanm":    {CVE: "CVE-2025-59734", Name: "SANM (ANIM Animation)", Severity: format.RiskCritical, Desc: "Use-after-free/OOB in SANM animation decoder"},
	"anim":    {CVE: "CVE-2025-59734", Name: "SANM (ANIM Animation)", Severity: format.RiskCritical, Desc: "Use-after-free/OOB in SANM animation decoder"},
	"rv60":    {CVE: "CVE-2025-69693", Name: "RealVideo 60", Severity: format.RiskHigh, Desc: "OOB read in RV60 slice parameter parsing"},
	"rv40":    {CVE: "CVE-2025-69693", Name: "RealVideo 40", Severity: format.RiskHigh, Desc: "Potential OOB in RealVideo decoder"},
	"rv30":    {CVE: "CVE-2025-69693", Name: "RealVideo 30", Severity: format.RiskHigh, Desc: "Potential OOB in RealVideo decoder"},
	"dhav":    {CVE: "CVE-2025-59729", Name: "DHAV (Dahua Video)", Severity: format.RiskHigh, Desc: "Integer underflow in DHAV file header parsing"},
	"j2k1":    {CVE: "CVE-2025-9951", Name: "JPEG 2000", Severity: format.RiskCritical, Desc: "Heap OOB write in JPEG2000 decomposition levels"},
	"mjp2":    {CVE: "CVE-2025-9951", Name: "JPEG 2000", Severity: format.RiskCritical, Desc: "Heap OOB write in JPEG2000 decomposition levels"},
	"jpeg":    {CVE: "CVE-2025-9951", Name: "JPEG/JPEG2000", Severity: format.RiskHigh, Desc: "Potential heap overflow in JPEG2000 decoder"},
	"mjpg":    {CVE: "CVE-2025-9951", Name: "Motion JPEG", Severity: format.RiskHigh, Desc: "Potential heap overflow in JPEG2000 decoder"},
	"als":     {CVE: "CVE-2025-7700", Name: "ALS (Audio Lossless)", Severity: format.RiskHigh, Desc: "ALS audio decoder block length OOB"},
	"dnx":     {CVE: "CVE-2021-38114", Name: "DNxHD", Severity: format.RiskHigh, Desc: "Heap buffer overflow in DNxHD extradata"},
	"cfhd":    {CVE: "CVE-2022-3966", Name: "CineForm HD", Severity: format.RiskMedium, Desc: "OOB read in CineForm HD plane dimensions"},
	"exr":     {CVE: "CVE-2025-59731", Name: "OpenEXR", Severity: format.RiskCritical, Desc: "OOB write in OpenEXR DWAA/DWAB compression"},
	"v_av1":   {CVE: "CVE-2026-40962", Name: "MKV AV1", Severity: format.RiskCritical, Desc: "Integer overflow in libsvtav1 encoding buffer sizing"},
	"v_vp9":   {CVE: "CVE-2026-40962", Name: "MKV VP9", Severity: format.RiskHigh, Desc: "Potential overflow via large VP9 frames"},
	"v_vp8":   {CVE: "CVE-2021-38291", Name: "MKV VP8", Severity: format.RiskHigh, Desc: "OOB read in image dimension computation"},
	"a_als":   {CVE: "CVE-2025-7700", Name: "MKV ALS Audio", Severity: format.RiskHigh, Desc: "ALS audio decoder block length OOB"},
}

type VulnerableCodecInfo struct {
	CVE      string
	Name     string
	Severity format.RiskLevel
	Desc     string
}

func checkVulnerableCodecPresent(fi *format.FormatInfo) []format.Anomaly {
	var found []format.Anomaly
	if fi.VideoCodecFourCC == "" && fi.AudioCodecFourCC == "" && len(fi.CodecList) == 0 {
		return nil
	}
	checked := make(map[string]bool)
	checkCodec := func(codec string) {
		if codec == "" || checked[codec] {
			return
		}
		checked[codec] = true
		lc := strings.ToLower(codec)
		for prefix, info := range VulnerableCodecs {
			if lc == prefix || strings.HasPrefix(lc, prefix) {
				found = append(found, format.Anomaly{
					Severity:    info.Severity,
					Category:    fmt.Sprintf("Vulnerable Codec: %s", info.Name),
					Description: fmt.Sprintf("Detected codec '%s' (%s) — %s [%s]", codec, info.Name, info.Desc, info.CVE),
					CVE:         info.CVE,
				})
				break
			}
		}
	}
	checkCodec(fi.VideoCodecFourCC)
	checkCodec(fi.AudioCodecFourCC)
	for _, c := range fi.CodecList {
		checkCodec(c)
	}
	return found
}

func RunSignatureChecks(fi *format.FormatInfo) []format.Anomaly {
	var allAnomalies []format.Anomaly
	for _, sig := range Signatures {
		for _, f := range sig.Formats {
			if f == fi.Type {
				anomalies := sig.Check(fi)
				allAnomalies = append(allAnomalies, anomalies...)
			}
		}
	}
	return allAnomalies
}

func ListSignatures() []Signature {
	return Signatures
}

func FormatSignaturesTable() string {
	table := fmt.Sprintf("%-20s %-8s %-12s %s\n", "CVE", "Severity", "Formats", "Description")
	table += fmt.Sprintf("%-20s %-8s %-12s %s\n", "----", "--------", "------", "-----------")
	for _, sig := range Signatures {
		formats := ""
		for i, f := range sig.Formats {
			if i > 0 {
				formats += "/"
			}
			formats += f.String()
		}
		table += fmt.Sprintf("%-20s %-8s %-12s %s\n", sig.CVE, sig.Severity, formats, sig.Title)
	}
	return table
}
