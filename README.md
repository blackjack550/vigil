# Vigil

**Video Vulnerability Pre-Checker** — 静默守望，不解码、不触发、不放过。

Vigil 是一个 Go 语言编写的 FFmpeg 漏洞预检器。它在 **不解码视频内容** 的前提下，通过底层容器结构解析 + 编码器 FourCC 检测 + 已知 CVE 签名匹配，对视频文件进行安全风险评估。发现 RCE 风险时自动标注评分并给出 FFmpeg 安全版本升级建议。发现威胁后可执行 **对称清除**（剥离非必要危险结构）。

---

## 核心原则

| 原则 | 实现 |
|------|------|
| ❌ 不触发漏洞 | 仅 `ReadAt` 字节级探读，不调用任何解码库 |
| ❌ 不读取视频流 | 只解析容器头结构（box/atom/element 元数据），跳过 mdat/cluster |
| ✅ 安全边界 | 每次读限 16MB，总探测量限 64MB，整数溢出防护 |
| ✅ 对称清除 | 识别并移除 JUNK/UDTA/未知 boxes，不破坏可用视频数据 |

## 架构

```
视频文件 → 底层探测引擎 (probe) → 容器格式解析器
                                    ├─ MP4/MOV — box 树 + stsd FourCC
                                    ├─ AVI     — RIFF + strf biCompression
                                    └─ MKV     — EBML + CodecID
                                         ↓
                               CVE 签名库 (30 条, 18 RCE)
                                         ↓
                          RCE 风险评分 + 安全版本建议 → 报告输出
                                         ↓
                              对称清除 (可选)
```

## 支持的 CVE 签名

共 **30 条签名**（18 条 RCE 风险），覆盖 CVE-2020 ~ CVE-2026：

### RCE 风险漏洞（评分 ≥ 9.0 Critical）

| CVE | 评分 | 类型 | 影响版本 | 安全版本 |
|-----|------|------|----------|----------|
| CVE-2026-40962 | **9.5** | AV1/svtav1 整数溢出→OOB写入 | < 8.1 | >= 8.1 |
| CVE-2025-59731 | **9.5** | OpenEXR DWAA 栈溢出 | < 7.1 | >= 7.1 |
| CVE-2020-22015 | **9.0** | stsz 整数溢出→堆溢出 | <= 4.3.2 | >= 4.3.3 |
| CVE-2026-12706 | **9.0** | RASC Use-After-Free | < 7.1 | >= 7.1 |
| CVE-2025-59734 | **9.0** | SANM Use-After-Free | < 7.1 | >= 7.1 |
| CVE-2025-9951 | **9.0** | JPEG2000 堆溢出 | < 7.1 | >= 7.1 |
| CVE-2025-22920 | **9.0** | 通用堆溢出 | < 7.1 | >= 7.1 |

### RCE 风险漏洞（评分 ≥ 8.0 High）

| CVE | 评分 | 类型 | 影响版本 | 安全版本 |
|-----|------|------|----------|----------|
| CVE-2021-38114 | 8.5 | DNxHD 堆溢出 | <= 4.4.1 | >= 4.4.2 |
| CVE-2022-3341 | 8.0 | demuxer 缓冲区溢出 | <= 5.1.2 | >= 5.1.3 |
| CVE-2023-47342 | 8.0 | OpenEXR 堆溢出 | <= 6.0 | >= 6.1 |
| CVE-2025-59729 | 8.0 | DHAV 整数下溢→堆溢出 | < 7.1 | >= 7.1 |
| CVE-2025-7700 | 8.0 | ALS 音频内存破坏 | < 7.1 | >= 7.1 |

### 其他漏洞（信息泄露/拒绝服务）

| CVE | 严重度 | 类型 |
|-----|--------|------|
| CVE-2021-38171 | High | trun box 负偏移 → OOB 读取 |
| CVE-2020-22033 | High | 索引表 chunk 偏移越界 |
| CVE-2021-38291 | High | 图像尺寸整数溢出 |
| CVE-2023-51794 | Medium | 音频滤波器 OOB |
| CVE-2022-3966 | Medium | CineForm OOB |
| CVE-2026-30997 | High | 全局参数提取 OOB |
| CVE-2025-59730 | High | SANM 帧解码 OOB |
| CVE-2025-69693 | High | RV60 切片 OOB |
| CVE-2025-10256 | Medium | Fireq NULL 解引用 |

### 编码器自动映射（CODECDETECT）

Vigil 从容器头部提取编码器 FourCC，自动关联对应 CVE 并给出升级建议：

| 检测到的编码器 | 关联 CVE | 评分 | 风险描述 | 安全版本 |
|---------------|----------|------|----------|----------|
| `rasc` / `ras` | CVE-2026-12706 | 9.0 | RASC UAF → **RCE** | >= 7.1 |
| `av01` / `av1` / `V_AV1` | CVE-2026-40962 | 9.5 | AV1/svtav1 整数溢出 | >= 8.1 |
| `sanm` / `anim` | CVE-2025-59734 | 9.0 | SANM UAF/OOB | >= 7.1 |
| `rv60` / `rv40` / `rv30` | CVE-2025-69693 | 8.0 | RealVideo OOB | >= 8.0.2 |
| `dhav` | CVE-2025-59729 | 8.0 | DHAV 整数下溢 → 堆溢出 | >= 7.1 |
| `j2k1` / `mjp2` | CVE-2025-9951 | 9.0 | JPEG2000 堆溢出 | >= 7.1 |
| `exr` | CVE-2025-59731 | 9.5 | EXR DWAA 栈溢出 → **RCE** | >= 7.1 |
| `als` / `A_ALS` | CVE-2025-7700 | 8.0 | ALS 音频 OOB | >= 7.1 |
| `dnx*` | CVE-2021-38114 | 8.5 | DNxHD 堆溢出 | >= 4.4.2 |
| `cfhd` | CVE-2022-3966 | 7.5 | CineForm OOB | >= 5.1.3 |

## 快速开始

```bash
# 构建
cd vigil
go build -o vigil.exe ./cmd/vigil/

# 扫描单个文件
vigil video.mp4

# 扫描目录（自动识别视频扩展名）
vigil ./videos/

# 递归扫描
vigil -r ./media/

# JSON 输出
vigil -json video.mp4

# 列出所有已知 CVE 签名
vigil signatures

# 详细模式（显示 box 树结构）
vigil -verbose video.mp4

# 对称清除预演（不实际修改文件）
vigil -dry-run video.mp4

# 执行对称清除（移除 JUNK/未知 boxes）
vigil -clean video.mp4
```

## 输出示例

### 干净文件
```
📄 Scanning: good.mp4
File:     good.mp4
Size:     1.2 MB
Format:   MP4
─────────────────────────────────────
✅ No anomalies detected
```

### 含 RCE 漏洞文件
```
📄 Scanning: exploit.mp4
File:     exploit.mp4
Size:     2.3 MB
Format:   MP4
─────────────────────────────────────
🔴 Risk Score: 9.0/10 (Critical)
   2 anomaly(ies) found

💀 🚨 RCE [9.0] [CVE-2026-12706] (affects < 7.1)
   affects: < 7.1 | Codec 'rasc' (RASC (Raster Animation)) has known RCE risks —
   Use-after-free in RASC video decoder [CVE-2026-12706].
   Upgrade FFmpeg to >= 7.1 to process safely
   ⬆ Upgrade FFmpeg to >= 7.1 for safe processing

🔴 🚨 RCE [7.5] [CVE-2023-49528] @0x20 (fixed in 6.1)
   affects: <= 6.0 | Box 'badd' has size 3 < minimum 8
```

### JSON 输出
```json
{
  "file": "video.mp4",
  "format": "MP4",
  "score": 9.0,
  "risk": "Critical",
  "safe": false,
  "anomalies": 2,
  "details": [
    {"severity":"Critical","category":"Vulnerable Codec","cve":"CVE-2026-12706"},
    {"severity":"High","category":"Negative trun data_offset","cve":"CVE-2021-38171"}
  ]
}
```

## 对称清除（对称清除）

检测到威胁后，Vigil 可以执行对称清除：

```bash
# 预演
vigil -dry-run suspicious.mp4

# 执行清除
vigil -clean suspicious.mp4
# 生成 suspicious_clean.mp4

# 自定义输出
vigil -clean -outdir ./clean_videos/ -suffix _sanitized video.mp4
```

清除操作：
- 移除 JUNK/FREE padding boxes（潜在隐写/漏洞载体）
- 移除未知/非标准 box 类型（潜在漏洞利用容器）
- 移除 udta/meta 元数据 box（常见攻击面）
- 保留 moov/trak/mdat 等核心结构（视频可用性）

## 开发

```bash
git clone <repo>
cd vigil
go build -o vigil.exe ./cmd/vigil/
go test ./... -v
go vet ./...
```

### 项目结构

```
vigil/
├── cmd/vigil/main.go            # CLI 入口
├── internal/
│   ├── probe/probe.go           # 安全文件探测引擎
│   ├── format/
│   │   ├── format.go            # 格式接口 + 编码器映射
│   │   ├── mp4.go               # MP4/MOV 解析器
│   │   ├── avi.go               # AVI 解析器
│   │   └── mkv.go               # MKV 解析器
│   ├── signatures/signatures.go # 30 条 CVE 签名
│   ├── assess/assess.go         # 风险评估引擎
│   └── sanitize/sanitize.go     # 对称清除模块
└── testdata/                    # 测试文件
```

## 测试

```bash
# 单元测试
go test ./... -v

# 端到端扫描测试
vigil testdata/
```

## 安全声明

Vigil 的设计目标是 **不触发** 它所检测的漏洞。它通过以下方式保证安全：

1. 底层 `ReadAt` 位置读取 + 大小限制（16MB 块，64MB 总量）
2. 只解析容器结构头，不解码任何编码后的媒体流
3. 所有算术运算有整数溢出防护
4. 不对文件内容做可执行解释

## License

MIT
