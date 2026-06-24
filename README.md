# Vigil

**Video Vulnerability Pre-Checker** — 静默守望，不解码、不触发、不放过。

Vigil 是一个 Go 语言编写的 FFmpeg 漏洞预检器。它在 **不解码视频内容** 的前提下，通过底层容器结构解析 + 编码器 FourCC 检测 + 已知 CVE 签名匹配，对视频文件进行安全风险评估。发现威胁后可执行 **对称清除**（剥离非必要危险结构）。

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
                               CVE 签名库 (30 条)
                                         ↓
                              风险评估 → 报告输出
                                         ↓
                              对称清除 (可选)
```

## 支持的 CVE 签名

共 **30 条签名**，覆盖 CVE-2020 ~ CVE-2026 全部高危/严重漏洞：

### 历史漏洞

| CVE | 严重度 | 影响范围 |
|-----|--------|----------|
| CVE-2023-49528 | High | MOV/MP4 box 大小整数回绕 → 堆溢出 |
| CVE-2022-3341 | High | 通用容器格式头部越界 |
| CVE-2021-38171 | High | trun box 负偏移 → OOB 读取 |
| CVE-2020-22015 | **Critical** | stsz sample 大小整数溢出 → 堆溢出 |
| CVE-2020-22033 | High | 索引表 chunk 偏移越界 |

### 2025-2026 最新漏洞

| CVE | 严重度 | 影响组件 | 检测方式 |
|-----|--------|----------|----------|
| CVE-2026-40962 | **Critical** | libavcodec/svtav1 | 检测 AV1 编码器 + 尺寸溢出 |
| CVE-2026-12706 | **Critical** | libavcodec/RASC | 检测 `rasc` FourCC |
| CVE-2026-8461 | **Critical** | libavcodec | 通用结构异常 → OOB 写入 |
| CVE-2026-6385 | **Critical** | 通用远程利用 | 多高风险管理累积 |
| CVE-2025-59731 | **Critical** | libavcodec/OpenEXR | 检测 EXR + DWAA 参数 |
| CVE-2025-59734 | **Critical** | libavcodec/SANM | 检测 `sanm`/`anim` FourCC |
| CVE-2025-9951 | **Critical** | libavcodec/JPEG2000 | 检测 `j2k1`/`mjp2` FourCC |
| CVE-2025-22920 | **Critical** | libavcodec | 帧缓冲区大小异常 |
| CVE-2026-30997 | High | libavcodec | 编码器参数提取异常 |
| CVE-2025-59729 | High | libavformat/DHAV | `dhav` 编码器检测 |
| CVE-2025-59730 | High | libavcodec/SANM | 帧维度异常 |
| CVE-2025-69693 | High | libavcodec/RV60 | 检测 `rv60`/`rv40` FourCC |
| CVE-2025-63757 | High | libswscale | 像素转换尺寸溢出 |
| CVE-2025-7700 | High | libavcodec/ALS | 检测 `als` 音频编码器 |
| CVE-2025-25473 | High | libavcodec | 参考帧参数异常 |
| CVE-2025-25469 | High | libavcodec | 内存分配异常 |

### 编码器自动映射（CODECDETECT）

Vigil 从容器头部提取编码器 FourCC，自动关联对应 CVE：

| 检测到的编码器 | 关联 CVE | 风险描述 |
|---------------|----------|----------|
| `rasc` / `ras` | CVE-2026-12706 | RASC UAF → **RCE** |
| `av01` / `av1` / `V_AV1` | CVE-2026-40962 | AV1/svtav1 整数溢出 |
| `sanm` / `anim` | CVE-2025-59734 | SANM UAF/OOB |
| `rv60` / `rv40` / `rv30` | CVE-2025-69693 | RealVideo OOB |
| `dhav` | CVE-2025-59729 | DHAV 整数下溢 |
| `j2k1` / `mjp2` | CVE-2025-9951 | JPEG2000 堆溢出 |
| `exr` | CVE-2025-59731 | EXR DWAA 栈溢出 → **RCE** |
| `als` / `A_ALS` | CVE-2025-7700 | ALS 音频 OOB |
| `dnx*` | CVE-2021-38114 | DNxHD 堆溢出 |
| `cfhd` | CVE-2022-3966 | CineForm OOB |

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

### 含漏洞文件
```
📄 Scanning: exploit.mp4
File:     exploit.mp4
Size:     2.3 MB
Format:   MP4
─────────────────────────────────────
🔴 Risk Score: 9.0/10 (Critical)
   2 anomaly(ies) found

💀 Vulnerable Codec: RASC (Raster Animation) [CVE-2026-12706]
   Detected codec 'rasc' (RASC (Raster Animation)) —
   Use-after-free in RASC video decoder [CVE-2026-12706]

🔴 Negative trun data_offset [CVE-2021-38171] @0x20
   trun data_offset=-1
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
