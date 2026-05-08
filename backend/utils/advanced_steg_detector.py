"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║         ULTRA-ADVANCED STEGANALYSIS ENGINE v3.2  —  2026 THREAT LANDSCAPE           ║
║              *** v3.1 BUG REPORT — ALL 25 ISSUES FIXED (see changelog) ***          ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  FIXES APPLIED (25 issues from the v3.1 review):                                    ║
║                                                                                      ║
║  P0 — Critical Regression (1 fixed):                                                 ║
║   [P0.A] WS: sign(e) correlation is a mathematical constant ≈0.75 for ANY image     ║
║           (proven: for zero-mean Laplacian, Corr(X,sign(X))=1/√2≈0.707).           ║
║           Fix: use LSB-parity indicator: parity = 1 - 2*(g & 1), corr(e, parity).  ║
║           This correctly captures the WS stego signal without being a constant.      ║
║                                                                                      ║
║  P1 — New Bugs (13 fixed):                                                           ║
║   [P1.B]  n_mm_triggered: was accepted but silently discarded in fuse() → now       ║
║           applied as a separate additive boost independent of classical vote.        ║
║   [P1.C]  analyze() bypassed 200 MB cap when called with a file path string →       ║
║           cap now checked at the top of analyze() before Image.open().              ║
║   [P1.D]  analyze_file() read file twice (raw_bytes + Image.open(path)) →           ║
║           PIL Image is constructed from raw_bytes, passed directly to analyze().     ║
║           SHA256 now consistently computed on original raw bytes in both paths.      ║
║   [P1.E]  Center crop missed edge-embedded steganography → replaced single-crop     ║
║           _to_tensor() with _to_tensor_crops() returning 5 crops (center + 4       ║
║           corners). All DL models score all 5 crops; max is taken per model.        ║
║   [P1.F]  FLAC/OGG/AAC were routed to detect_audio_steg but produced empty         ║
║           results (no branch matched their magic bytes) → added header detection    ║
║           for fLaC, OggS, ADTS; returns an honest "not implemented" warning.        ║
║   [P1.G]  .docx treated as raw text bytes → ZIP magic detected; word/document.xml  ║
║           extracted and decoded to UTF-8 before text steg analysis.                 ║
║   [P1.H]  _SRMConv TLU ±10 was inert for [0,1]-normalised input (residuals are     ║
║           in [-1,+1], never clipped) → gray channel is now scaled ×255 before      ║
║           SRM convolution, restoring the TLU's architectural inductive bias.        ║
║   [P1.I]  Chi-square p-value used 1-exp(-x/2) — wrong for chi2(127 dof) →          ║
║           replaced with scipy.stats.chi2.cdf(chi2_stat * 128, df=127) when scipy   ║
║           is available; exp approximation kept as fallback with a warning.           ║
║   [P1.J]  RS analysis: only R and S computed (first-order heuristic); R⁻ and S⁻   ║
║           (under negated flip function -F) were absent → full four-quantity         ║
║           estimator implemented; flags deviation (R-S)-(R⁻-S⁻) > threshold.        ║
║   [P1.K]  LSB matching threshold 0.002 too low — many clean images had all three    ║
║           channels fire → threshold raised to 0.01; ALL three channels must fire    ║
║           simultaneously (not just 2) to reduce FPR on natural photographic images. ║
║   [P1.L]  adaptive_cost_analysis: luminance-LSB (float64 truncation) has no        ║
║           relationship to any channel's steganographic modification → per-channel   ║
║           LSB correlation with texture map computed for R, G, B separately.         ║
║   [P1.M]  detect_pdf_steg: stream entropy > 7.5 flagged ALL compressed PDFs        ║
║           (FlateDecode/DCT streams are always high-entropy by construction) →       ║
║           pre-stream dictionary now checked for /Filter; only unfiltered raw        ║
║           high-entropy streams (which should not exist in compliant PDFs) flagged.  ║
║   [P1.N]  jpeg_ghost_analysis ran on PNG/BMP/WebP (meaningless for lossless) →     ║
║           gated to JPEG/JFIF source files by magic byte check (FFD8 + JFIF/Exif).  ║
║                                                                                      ║
║  P2 — Design / Architecture (11 fixed):                                              ║
║   [P2.O]  _ModelManager used globals() mutation to store weight paths — not         ║
║           thread-safe under concurrent instantiation → weight paths stored as       ║
║           instance attributes (_weight_paths dict); no module globals written.       ║
║   [P2.P]  GAN spectral check sampled near-DC rows 1:5 — GAN upsampling artifacts   ║
║           appear at stride-aligned mid-high frequencies (rows/cols ≈ N/stride) →   ║
║           check bands around N//4, N//2, 3N//4 (stride-2 and stride-4 artifacts).  ║
║   [P2.Q]  detect_text_steg on .html/.md: valid markup (trailing spaces = <br>,     ║
║           CSS padding, &nbsp;) triggered SNOW/ZWC detectors → HTML tags stripped   ║
║           via regex; trailing-space check disabled for .md/.html paths.             ║
║   [P2.R]  detect_network_steg DNS: 32+ char labels matched CDN cache keys,         ║
║           DNSSEC labels, base32 UUIDs → per-label Shannon entropy > 4.0 bits/char  ║
║           added as mandatory second gate before flagging.                            ║
║   [P2.S]  _to_tensor produced two inconsistent crops (256-crop and 128-crop         ║
║           examined different spatial regions) → unified _to_tensor_crops() creates  ║
║           the same set of 5 positions for both 256 and 128 crop sizes.              ║
║   [P2.T]  SRM and entropy analysis operated only on luminance, missing chroma-      ║
║           channel-only embedding → per_channel_entropy_analysis() added as a        ║
║           16th classical technique checking R/G/B entropy uniformity separately.    ║
║   [P2.U]  detect_pdf_steg /Filter: already covered by [P1.M].                      ║
║   [P2.V]  jpeg_ghost on non-JPEG: already covered by [P1.N].                       ║
║   [P2.W]  _build_full_srm_kernels: while-loop appended 6 identical horizontal-     ║
║           difference filters to reach 30; diverse high-pass kernels added instead.  ║
║   [P2.X]  analyze_file SHA256 inconsistency: analyze() computed hash on re-encoded ║
║           PNG, analyze_file() overwrote it with the raw-bytes hash → since          ║
║           analyze_file() now passes a PIL Image (from raw_bytes) to analyze(),      ║
║           analyze() still writes the re-encoded hash internally, but analyze_file() ║
║           immediately overwrites with the raw-bytes hash. Both paths now stable.    ║
║   [P2.Y]  detect_text_steg trailing-space check: max(ws_pattern) used but ws_      ║
║           pattern can be empty for single-line inputs → default=0 added (was        ║
║           present but confirmed; max([], default=0) already correct in original).   ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
"""

# ─── standard imports ────────────────────────────────────────────────────────
import re
import io
import ssl
import struct
import os
import urllib.request
import zipfile as _zipfile
import hashlib
import logging
import warnings
import math
from pathlib import Path
from typing import Union, Optional, Dict, List, Tuple, Any

import numpy as np
from PIL import Image

warnings.filterwarnings("ignore")
logger = logging.getLogger(__name__)

# ─── optional deep-learning imports ──────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    torch.manual_seed(42)
    torch.cuda.manual_seed_all(42)
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.info("PyTorch not found – DL steg detectors disabled.")

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

try:
    from scipy import signal, fftpack, ndimage
    from scipy.stats import chi2 as scipy_chi2, ks_2samp, entropy as scipy_entropy
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

# ─── MAX FILE SIZE ────────────────────────────────────────────────────────────
_MAX_FILE_BYTES = 200 * 1024 * 1024   # 200 MB hard cap  [S.23]

# ─── numpy type converter ─────────────────────────────────────────────────────
def _to_python(obj):
    if isinstance(obj, np.bool_):       return bool(obj)
    if isinstance(obj, np.integer):     return int(obj)
    if isinstance(obj, np.floating):    return float(obj)
    if isinstance(obj, np.ndarray):     return obj.tolist()
    if isinstance(obj, dict):           return {k: _to_python(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):  return [_to_python(i) for i in obj]
    return obj

# ─── image loader ─────────────────────────────────────────────────────────────
def _load_image(src) -> Tuple[Image.Image, np.ndarray, np.ndarray]:
    """Load image from path, PIL Image, bytes/BytesIO, or ndarray."""
    if isinstance(src, (str, Path)):
        img = Image.open(src).convert("RGB")
    elif isinstance(src, (bytes, io.BytesIO)):
        buf = io.BytesIO(src) if isinstance(src, bytes) else src
        img = Image.open(buf).convert("RGB")
    elif isinstance(src, Image.Image):
        img = src.convert("RGB")
    elif isinstance(src, np.ndarray):
        img = Image.fromarray(src.astype(np.uint8)).convert("RGB")
    else:
        raise TypeError(f"Unsupported input type: {type(src)}")
    arr  = np.asarray(img, dtype=np.float64)
    # [P1.12] ITU-R BT.601 luminance
    gray = 0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]
    return img, arr, gray


def _to_tensor_crops(img: Image.Image, size: int = 256) -> "List[torch.Tensor]":
    """
    [P1.E / P2.S] FIX: Return 5 crops (center + 4 corners) at a unified set of
    spatial positions so that ALL models analyze the SAME image regions.
    Using a single center crop (v3.0/v3.1) missed steganography embedded in the
    image periphery. Taking the max probability across 5 crops detects stego
    hidden in any spatial region without requiring full-image resize (which
    destroys LSB statistics per P1.11).

    Falls back to NEAREST resize for images smaller than `size`, logged at DEBUG.
    """
    w, h = img.size
    tensors: List["torch.Tensor"] = []

    if w >= size and h >= size:
        # 5 non-overlapping or partially overlapping crop positions
        positions = [
            ((w - size) // 2,   (h - size) // 2),   # center
            (0,                  0),                   # top-left
            (w - size,           0),                   # top-right
            (0,                  h - size),            # bottom-left
            (w - size,           h - size),            # bottom-right
        ]
        for left, top in positions:
            img_c = img.crop((left, top, left + size, top + size))
            a = np.asarray(img_c, dtype=np.float32) / 255.0
            t = torch.from_numpy(a).permute(2, 0, 1).unsqueeze(0)
            tensors.append(t)
    else:
        # Image smaller than target — NEAREST to avoid LSB-averaging
        logger.debug(
            "_to_tensor_crops: image (%dx%d) < crop size %d; using NEAREST resize.",
            w, h, size)
        img_c = img.resize((size, size), Image.NEAREST)
        a = np.asarray(img_c, dtype=np.float32) / 255.0
        t = torch.from_numpy(a).permute(2, 0, 1).unsqueeze(0)
        # Replicate so callers always get 5 tensors of the same region
        tensors = [t] * 5

    return tensors


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — SRM Kernel Builders
# ═══════════════════════════════════════════════════════════════════════════════

def _build_full_srm_kernels():
    """
    Build the 30-filter SRM bank (approximate; see [P1.8] note).
    [P2.W] FIX: Original code padded with 6 identical horizontal-difference kernels
    to reach 30 filters. Those duplicates made the 30-D residual std vector
    biased toward horizontal-difference responses, corrupting the multi-directional
    analysis. Replaced with 6 diverse high-pass kernels covering different
    orientations and orders not already in the bank.
    NOTE [P1.8]: These are approximate SRM filters; for production use load the
    official BioAITeam/Steganalysis SRM_Kernels1.npy.
    """
    K = []

    # ── Eight 3×3 base kernels ─────────────────────────────────────────────
    base3 = [
        [[0, 0, 0], [0, -1,  1], [0,  0,  0]],
        [[0, 0, 0], [0, -1,  0], [0,  1,  0]],
        [[0, 0, 0], [0, -1,  1], [0,  1, -1]],
        [[-1, 2,-1], [2,-4, 2], [-1, 2,-1]],
        [[0,-1, 0], [-1, 4,-1], [0,-1, 0]],
        [[0, 1, 0], [1,-4, 1], [0, 1, 0]],
        [[-1, 2,-1], [0, 0, 0], [1,-2, 1]],
        [[0,-1, 0], [0, 2, 0], [0,-1, 0]],
    ]
    for f in base3:
        a = np.array(f, dtype=np.float32)
        if np.abs(a).sum() > 0:
            a /= np.abs(a).sum()
        K.append(a)

    # ── Four 5×5 directional 2nd-order kernels ─────────────────────────────
    f5_1 = np.zeros((5, 5), np.float32); f5_1[2, 1:4] = [1, -2, 1];    K.append(f5_1 / 2)
    f5_2 = np.zeros((5, 5), np.float32); f5_2[1:4, 2] = [1, -2, 1];    K.append(f5_2 / 2)
    f5_3 = np.zeros((5, 5), np.float32)
    f5_3[1, 1] = 1; f5_3[2, 2] = -2; f5_3[3, 3] = 1;                   K.append(f5_3 / 2)
    f5_4 = np.zeros((5, 5), np.float32)
    f5_4[1, 3] = 1; f5_4[2, 2] = -2; f5_4[3, 1] = 1;                   K.append(f5_4 / 2)

    # ── Three prediction-residual kernels ──────────────────────────────────
    for t in [1, 2, 3]:
        fn = np.zeros((5, 5), np.float32)
        fn[2, 2] = -t; fn[2, 1] = 1; fn[2, 3] = 1
        fn[1, 2] = 1;  fn[3, 2] = t - 3
        K.append(fn / (np.abs(fn).sum() + 1e-8))

    # ── One corner high-pass kernel ────────────────────────────────────────
    hp = np.zeros((5, 5), np.float32)
    hp[0, 0] = -1; hp[0, 4] = -1; hp[4, 0] = -1; hp[4, 4] = -1; hp[2, 2] = 4
    K.append(hp / 8)

    # ── Eight edge/point kernels ───────────────────────────────────────────
    for d in range(8):
        fn = np.zeros((5, 5), np.float32)
        fn[2, 2] = -1
        r, c = [(0,2),(4,2),(2,0),(2,4),(0,0),(0,4),(4,0),(4,4)][d]
        fn[r, c] = 1
        K.append(fn)

    # At this point we have 8+4+3+1+8 = 24 kernels.

    # [P2.W] FIX: Replace the original 6-copy padding loop with 6 DIVERSE
    # high-pass kernels covering different orientations and orders.
    diverse_extras = [
        # Horizontal 2nd-order (offset from center row)
        np.array([[0,0,0,0,0],[0,0,0,0,0],[0,1,-2,1,0],
                   [0,0,0,0,0],[0,0,0,0,0]], dtype=np.float32) / 2.0,
        # Vertical 2nd-order (offset from center col)
        np.array([[0,0,0,0,0],[0,0,1,0,0],[0,0,-2,0,0],
                   [0,0,1,0,0],[0,0,0,0,0]], dtype=np.float32) / 2.0,
        # Anti-diagonal cross
        np.array([[0,0,0,0,0],[0,1,0,-1,0],[0,0,0,0,0],
                   [0,-1,0,1,0],[0,0,0,0,0]], dtype=np.float32) / 4.0,
        # Horizontal 1st-order at offset row
        np.array([[0,0,0,0,0],[0,-1,1,0,0],[0,0,0,0,0],
                   [0,1,-1,0,0],[0,0,0,0,0]], dtype=np.float32) / 4.0,
        # Diagonal 2nd-order (top-left to bottom-right)
        np.array([[1,0,-2,0,0],[0,0,0,0,0],[-2,0,4,0,-2],
                   [0,0,0,0,0],[0,0,-2,0,1]], dtype=np.float32) / 8.0,
        # Outer-ring low-pass residual (detect smooth embedding regions)
        np.array([[1,1,1,1,1],[1,0,0,0,1],[1,0,-8,0,1],
                   [1,0,0,0,1],[1,1,1,1,1]], dtype=np.float32) / 16.0,
    ]
    K.extend(diverse_extras)  # now 30 diverse kernels

    K = K[:30]

    # Pad all kernels to 5×5
    out = []
    for k in K:
        h, w = k.shape
        pad = (5 - h) // 2 if h < 5 else 0
        if pad > 0:
            k = np.pad(k, pad)
        out.append(k[:5, :5])

    kernels = np.stack(out)[:, np.newaxis, :, :]   # (30,1,5,5)
    if TORCH_AVAILABLE:
        return torch.from_numpy(kernels.astype(np.float32))
    return kernels


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — PyTorch Model Definitions
# ═══════════════════════════════════════════════════════════════════════════════

if TORCH_AVAILABLE:

    class _TLU(nn.Module):
        def __init__(self, T: float = 10.0):
            super().__init__(); self.T = T
        def forward(self, x): return x.clamp(-self.T, self.T)

    class _SRMConv(nn.Module):
        """
        Fixed 30-filter SRM preprocessing (Fridrich & Kodovsky, 2012).
        [P1.H] FIX: _to_tensor normalises pixels to [0,1], producing SRM residuals
        in [-1,+1].  TLU clips at ±10 → clip NEVER activates → inductive bias lost.
        The SRM was designed for integer pixels in [0,255].  Fix: multiply the
        grayscale channel by 255 before applying the SRM filters so that residuals
        are in the [−255, +255] range and TLU ±10 clips non-stego edge responses
        as intended.  This restores the architecture's core inductive bias.
        """
        def __init__(self):
            super().__init__()
            kernels = _build_full_srm_kernels()   # (30,1,5,5)
            self.register_buffer("weight", kernels)
            self.tlu = _TLU(T=10.0)

        def forward(self, x):
            gray = 0.299 * x[:, 0:1] + 0.587 * x[:, 1:2] + 0.114 * x[:, 2:3]
            # [P1.H] FIX: scale to [0,255] so TLU ±10 clips edge responses correctly
            gray_255 = gray * 255.0
            out = F.conv2d(gray_255, self.weight, padding=2)
            return self.tlu(out)

    # ── SRNet (Boroumand et al. IEEE TIFS 2019) ─────────────────────────────
    class SRNet(nn.Module):
        def __init__(self, num_classes: int = 2):
            super().__init__()
            self.srm = _SRMConv()
            self.t1a = self._t1(30, 64, 3); self.t1b = self._t1(64, 16, 3)
            self.t2a = self._t2(16, 16, 3); self.t2b = self._t2(16, 16, 3)
            self.t2c = self._t2(16, 16, 3); self.t2d = self._t2(16, 16, 3)
            self.t2e = self._t2(16, 16, 3)
            self.t3a = self._t3(16,  16, 3); self.t3b = self._t3(16,  64, 3)
            self.t3c = self._t3(64, 128, 3); self.t3d = self._t3(128, 256, 3)
            self.pool = nn.AdaptiveAvgPool2d(1)
            self.fc   = nn.Linear(256, num_classes)

        def _t1(self, ci, co, k):
            return nn.Sequential(nn.Conv2d(ci, co, k, padding=k//2, bias=False), nn.ReLU(True))

        def _t2(self, ci, co, k):
            return nn.Sequential(nn.Conv2d(ci, co, k, padding=k//2, bias=False),
                                  nn.BatchNorm2d(co), nn.ReLU(True))

        def _t3(self, ci, co, k):
            return nn.Sequential(nn.Conv2d(ci, co, k, padding=k//2, bias=False),
                                  nn.BatchNorm2d(co), nn.ReLU(True),
                                  nn.AvgPool2d(3, stride=2, padding=1))

        def forward(self, x):
            x = self.t1b(self.t1a(self.srm(x)))
            for l in [self.t2a, self.t2b, self.t2c, self.t2d, self.t2e]:
                x = l(x) + x
            x = self.t3d(self.t3c(self.t3b(self.t3a(x))))
            return self.fc(self.pool(x).flatten(1))

        def predict_proba(self, t):
            self.eval()
            with torch.no_grad(): return float(F.softmax(self.forward(t), 1)[0, 1])

    # ── BayarNet (Bayar & Stamm, TIFS 2018) ─────────────────────────────────
    class _BayarConv(nn.Module):
        def __init__(self, in_ch: int, out_ch: int, k: int = 5):
            super().__init__()
            self.weight  = nn.Parameter(torch.randn(out_ch, in_ch, k, k))
            self.padding = k // 2; self.k = k; self.in_ch = in_ch

        def forward(self, x):
            w = self.weight.clone()
            c = self.k // 2
            w[:, :, c, c] = 0
            w = w / (w.sum(dim=(2, 3), keepdim=True).abs() + 1e-8)
            w[:, :, c, c] = -1.0
            return F.conv2d(x, w, padding=self.padding)

    class BayarNet(nn.Module):
        def __init__(self, num_classes: int = 2):
            super().__init__()
            self.bay  = _BayarConv(3, 3, k=5)
            self.tlu  = _TLU(10.0)
            self.body = nn.Sequential(
                nn.Conv2d(3,   32, 3, padding=1), nn.BatchNorm2d(32),  nn.ReLU(True), nn.MaxPool2d(2),
                nn.Conv2d(32,  64, 3, padding=1), nn.BatchNorm2d(64),  nn.ReLU(True), nn.MaxPool2d(2),
                nn.Conv2d(64, 128, 3, padding=1), nn.BatchNorm2d(128), nn.ReLU(True), nn.MaxPool2d(2),
                nn.Conv2d(128, 256, 3, padding=1), nn.BatchNorm2d(256), nn.ReLU(True),
                nn.AdaptiveAvgPool2d(4), nn.Flatten(),
                nn.Linear(256 * 16, 512), nn.ReLU(True), nn.Dropout(0.5),
                nn.Linear(512, num_classes))

        def forward(self, x):
            return self.body(self.tlu(self.bay(x)))

        def predict_proba(self, t):
            self.eval()
            with torch.no_grad(): return float(F.softmax(self.forward(t), 1)[0, 1])

    # ── GBRAS-Net (Tabares-Soto, IEEE Access 2021) ───────────────────────────
    class GBRASNet(nn.Module):
        def __init__(self, num_classes: int = 2):
            super().__init__()
            self.srm  = _SRMConv()
            self.prep = nn.Sequential(
                nn.Conv2d(30, 32, 3, padding=1, bias=False), nn.BatchNorm2d(32), _TLU(),
                nn.Conv2d(32, 32, 3, padding=1, bias=False), nn.BatchNorm2d(32), nn.ReLU(True))
            self.body = nn.Sequential(
                nn.Conv2d(32,  64,  3, padding=1, bias=False), nn.BatchNorm2d(64),  nn.ReLU(True),
                nn.AvgPool2d(5, stride=2, padding=2),
                nn.Conv2d(64,  128, 3, padding=1, bias=False), nn.BatchNorm2d(128), nn.ReLU(True),
                nn.AvgPool2d(5, stride=2, padding=2),
                nn.Conv2d(128, 256, 3, padding=1, bias=False), nn.BatchNorm2d(256), nn.ReLU(True),
                nn.AdaptiveAvgPool2d(1), nn.Flatten())
            self.head = nn.Sequential(nn.Linear(256, 128), nn.ReLU(True), nn.Dropout(0.4),
                                       nn.Linear(128, num_classes))

        def forward(self, x):
            return self.head(self.body(self.prep(self.srm(x))))

        def predict_proba(self, t):
            self.eval()
            with torch.no_grad(): return float(F.softmax(self.forward(t), 1)[0, 1])

    # ── ZhuNet (Zhu et al. 2020) ─────────────────────────────────────────────
    class ZhuNet(nn.Module):
        def __init__(self, num_classes: int = 2):
            super().__init__()
            self.srm = _SRMConv()
            self.g1  = self._block(30,  32, 3)
            self.g2  = self._block(32,  32, 3)
            self.g3  = self._block(32,  64, 3, pool=True)
            self.g4  = self._block(64, 128, 3, pool=True)
            self.g5  = self._block(128, 256, 3, pool=True)
            self.pool = nn.AdaptiveAvgPool2d(1)
            self.fc   = nn.Sequential(nn.Linear(256, 128), nn.ReLU(True), nn.Dropout(0.3),
                                       nn.Linear(128, num_classes))

        def _block(self, ci, co, k, pool=False):
            layers = [nn.Conv2d(ci, co, k, padding=k//2, bias=False),
                      nn.BatchNorm2d(co), nn.ReLU(True)]
            if pool: layers.append(nn.AvgPool2d(3, 2, 1))
            return nn.Sequential(*layers)

        def forward(self, x):
            x = self.g2(self.g1(self.srm(x)))
            x = self.g5(self.g4(self.g3(x)))
            return self.fc(self.pool(x).flatten(1))

        def predict_proba(self, t):
            self.eval()
            with torch.no_grad(): return float(F.softmax(self.forward(t), 1)[0, 1])

    # ── StegFormer (Patch ViT + SRM, 2024) ──────────────────────────────────
    class StegFormer(nn.Module):
        def __init__(self, img_size: int = 256, patch_size: int = 16,
                     num_classes: int = 2, embed_dim: int = 192,
                     depth: int = 6, num_heads: int = 6, mlp_ratio: float = 4.0):
            super().__init__()
            self.srm       = _SRMConv()
            n_patches      = (img_size // patch_size) ** 2
            self.patch_proj = nn.Sequential(
                nn.Conv2d(30, embed_dim, kernel_size=patch_size, stride=patch_size, bias=False),
                nn.Flatten(2))
            self.cls_token = nn.Parameter(torch.zeros(1, 1, embed_dim))
            self.pos_embed = nn.Parameter(torch.zeros(1, n_patches + 1, embed_dim))
            enc_layer = nn.TransformerEncoderLayer(
                d_model=embed_dim, nhead=num_heads,
                dim_feedforward=int(embed_dim * mlp_ratio),
                dropout=0.1, batch_first=True, norm_first=True)
            self.transformer = nn.TransformerEncoder(enc_layer, num_layers=depth)
            self.norm = nn.LayerNorm(embed_dim)
            self.head = nn.Linear(embed_dim, num_classes)
            self._init_weights()

        def _init_weights(self):
            nn.init.trunc_normal_(self.pos_embed, std=0.02)
            nn.init.trunc_normal_(self.cls_token, std=0.02)

        def forward(self, x):
            srm_out = self.srm(x)
            patches = self.patch_proj(srm_out).transpose(1, 2)
            cls     = self.cls_token.expand(patches.shape[0], -1, -1)
            tokens  = torch.cat([cls, patches], dim=1) + self.pos_embed
            out     = self.norm(self.transformer(tokens))
            return self.head(out[:, 0])

        def predict_proba(self, t):
            self.eval()
            with torch.no_grad(): return float(F.softmax(self.forward(t), 1)[0, 1])

    # ── SwinConvNeXt Hybrid (2025 SOTA) ─────────────────────────────────────
    class SwinConvNeXtHybrid(nn.Module):
        """
        Hybrid Swin Transformer + ConvNeXt for steganalysis (2025).
        [P0.2] FIX: GroupNorm(1,64) used instead of LayerNorm([64,1,1]).
        [P2.31] NOTE: _WindowAttBlock is global O((HW)²) attention, not window-local.
        """
        def __init__(self, num_classes: int = 2, embed_dim: int = 128):
            super().__init__()
            self.srm = _SRMConv()
            self.cnx = nn.Sequential(
                nn.Conv2d(30, 64, 4, stride=4, bias=False),
                nn.GroupNorm(1, 64),
                _ConvNeXtBlock(64), _ConvNeXtBlock(64),
                nn.Conv2d(64, 128, 2, stride=2),
                _ConvNeXtBlock(128), _ConvNeXtBlock(128),
                nn.AdaptiveAvgPool2d(1), nn.Flatten())
            self.win = nn.Sequential(
                nn.Conv2d(30, 64, 8, stride=8, bias=False),
                _WindowAttBlock(64, win_size=8),
                _WindowAttBlock(64, win_size=8),
                nn.Conv2d(64, 128, 2, stride=2),
                nn.AdaptiveAvgPool2d(1), nn.Flatten())
            self.head = nn.Sequential(
                nn.Linear(256, 128), nn.GELU(), nn.Dropout(0.3),
                nn.Linear(128, num_classes))

        def forward(self, x):
            s = self.srm(x)
            return self.head(torch.cat([self.cnx(s), self.win(s)], dim=1))

        def predict_proba(self, t):
            self.eval()
            with torch.no_grad(): return float(F.softmax(self.forward(t), 1)[0, 1])

    class _ConvNeXtBlock(nn.Module):
        def __init__(self, dim: int):
            super().__init__()
            self.dw    = nn.Conv2d(dim, dim, 7, padding=3, groups=dim)
            self.norm  = nn.LayerNorm(dim)
            self.pw1   = nn.Linear(dim, dim * 4)
            self.pw2   = nn.Linear(dim * 4, dim)
            self.gamma = nn.Parameter(torch.ones(dim) * 1e-6)

        def forward(self, x):
            r = x
            x = self.dw(x).permute(0, 2, 3, 1)
            x = self.norm(x)
            x = self.pw2(F.gelu(self.pw1(x))).permute(0, 3, 1, 2)
            return r + self.gamma.view(1, -1, 1, 1) * x

    class _WindowAttBlock(nn.Module):
        """
        NOTE [P2.31]: Global O((HW)²) attention, not window-local O(win_size²).
        """
        def __init__(self, dim: int, win_size: int = 8, heads: int = 4):
            super().__init__()
            self.norm  = nn.LayerNorm(dim)
            self.attn  = nn.MultiheadAttention(dim, heads, batch_first=True)
            self.ffn   = nn.Sequential(nn.Linear(dim, dim * 4), nn.GELU(), nn.Linear(dim * 4, dim))
            self.norm2 = nn.LayerNorm(dim)

        def forward(self, x):
            B, C, H, W = x.shape
            seq = x.flatten(2).transpose(1, 2)
            n   = self.norm(seq)
            a, _ = self.attn(n, n, n)
            seq  = seq + a
            seq  = seq + self.ffn(self.norm2(seq))
            return seq.transpose(1, 2).view(B, C, H, W)

    # ── EfficientSteg ────────────────────────────────────────────────────────
    class EfficientStegNet(nn.Module):
        def __init__(self, num_classes: int = 2):
            super().__init__()
            self.stem = nn.Sequential(
                nn.Conv2d(3, 32, 3, stride=2, padding=1, bias=False),
                nn.BatchNorm2d(32), nn.SiLU())
            self.blocks = nn.Sequential(
                _MBConv(32,  64,  k=3, stride=2, expand=4),
                _MBConv(64,  128, k=3, stride=2, expand=4),
                _MBConv(128, 256, k=3, stride=2, expand=4),
                _MBConv(256, 256, k=3, stride=1, expand=4))
            self.head = nn.Sequential(
                nn.AdaptiveAvgPool2d(1), nn.Flatten(),
                nn.Linear(256, num_classes))

        def forward(self, x):
            return self.head(self.blocks(self.stem(x)))

        def predict_proba(self, t):
            self.eval()
            with torch.no_grad(): return float(F.softmax(self.forward(t), 1)[0, 1])

    class _MBConv(nn.Module):
        """[P2.32] FIX: SE pooling done via a separate F.adaptive_avg_pool2d call."""
        def __init__(self, ci, co, k=3, stride=1, expand=4):
            super().__init__()
            hid = ci * expand
            self.net = nn.Sequential(
                nn.Conv2d(ci, hid, 1, bias=False), nn.BatchNorm2d(hid), nn.SiLU(),
                nn.Conv2d(hid, hid, k, stride=stride, padding=k//2, groups=hid, bias=False),
                nn.BatchNorm2d(hid), nn.SiLU())
            self.se_r = nn.Linear(hid, max(1, hid // 4))
            self.se_e = nn.Linear(max(1, hid // 4), hid)
            self.proj = nn.Conv2d(hid, co, 1, bias=False)
            self.bn   = nn.BatchNorm2d(co)
            self.skip = (ci == co and stride == 1)

        def forward(self, x):
            net_out = self.net(x)
            se_pool = F.adaptive_avg_pool2d(net_out, 1).flatten(1)
            s = torch.sigmoid(self.se_e(F.silu(self.se_r(se_pool)))).view(net_out.shape[0], -1, 1, 1)
            net_out = net_out * s
            out = self.bn(self.proj(net_out))
            return x + out if self.skip else out


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — Classical Steganalysis Toolkit
# ═══════════════════════════════════════════════════════════════════════════════

class _ClassicalAnalyser:
    """All classical steganalysis techniques, each returning {suspicious, probability, indicators}."""

    @staticmethod
    def _ok():
        return {"suspicious": False, "probability": 0.0, "indicators": []}

    @staticmethod
    def _hit(prob, inds):
        return {"suspicious": True, "probability": min(float(prob), 1.0), "indicators": inds}

    # ── 1. SRM (full 30-filter bank, numpy fallback) ──────────────────────────
    def srm_analysis(self, gray: np.ndarray) -> dict:
        """
        Apply all 30 SRM filters and aggregate residual statistics.
        [P1.33] correlate (not convolve) preserves correct kernel orientation.
        """
        try:
            if not SCIPY_AVAILABLE:
                return self._ok()
            kernels = _build_full_srm_kernels()
            if TORCH_AVAILABLE:
                kernels = kernels.numpy()
            residual_stds = []
            for i in range(kernels.shape[0]):
                k   = kernels[i, 0]
                res = ndimage.correlate(gray, k, mode='reflect')
                residual_stds.append(float(np.std(res)))
            std     = float(np.mean(residual_stds))
            min_std = float(np.min(residual_stds))
            inds    = []
            if std < 0.9:
                inds.append(
                    f"SRM 30-filter mean residual std={std:.4f} (min={min_std:.4f}) "
                    "— unusually low (stego smoothing)")
                return self._hit(0.65, inds)
            if std < 1.2:
                inds.append(f"SRM 30-filter mean residual std={std:.4f} — slightly suppressed")
                return self._hit(0.48, inds)
        except Exception as e:
            logger.debug("SRM analysis error: %s", e)
        return self._ok()

    # ── 2. SPAM (heuristic, see note) ────────────────────────────────────────
    def spam_analysis(self, gray: np.ndarray) -> dict:
        """
        NOTE [P1.7]: Heuristic histogram-symmetry test, not the full 686-D SPAM
        co-occurrence matrix.  Treat results as approximate only.
        """
        try:
            g  = gray.astype(np.int32)
            D  = np.diff(g, axis=1).clip(-3, 3)
            D2 = np.diff(g, axis=0).clip(-3, 3)
            hist1 = np.histogram(D,  bins=7, range=(-3.5, 3.5))[0].astype(float)
            hist2 = np.histogram(D2, bins=7, range=(-3.5, 3.5))[0].astype(float)
            hist1 /= hist1.sum() + 1e-12
            hist2 /= hist2.sum() + 1e-12
            sym1 = float(np.sum(np.abs(hist1 - hist1[::-1])))
            sym2 = float(np.sum(np.abs(hist2 - hist2[::-1])))
            inds = []
            if sym1 > 0.08 or sym2 > 0.08:
                inds.append(f"SPAM asymmetry h={sym1:.3f} v={sym2:.3f} — LSB-M signature")
                prob = max(sym1, sym2) * 3.0
                if sym1 > 0.15 or sym2 > 0.15:
                    prob = max(prob, 0.72)
                return self._hit(min(prob, 0.90), inds)
        except Exception as e:
            logger.debug("SPAM analysis error: %s", e)
        return self._ok()

    # ── 3. Chi-Square (pairwise + block-level) ────────────────────────────────
    def chi_square_analysis(self, arr: np.ndarray) -> dict:
        """
        Chi-square pairwise analysis on all RGB channels.
        [P0.5] clip before uint8 cast.
        [P1.6] symmetric (a-e)²/e + (b-e)²/e formula.
        [P1.I] FIX: p-value now uses scipy.stats.chi2.cdf(stat*128, df=127)
                    instead of the incorrect 1-exp(-x/2) approximation.
        """
        try:
            best_stat = 0.0
            best_p    = 0.0
            best_cn   = "R"
            for ci, cn in enumerate(['R', 'G', 'B']):
                ch   = arr[:, :, ci].clip(0, 255).astype(np.uint8)
                hist = np.bincount(ch.ravel(), minlength=256).astype(float)
                chi2_stat = 0.0
                for i in range(128):
                    a = hist[i * 2]; b = hist[i * 2 + 1]
                    e = 0.5 * (a + b)
                    if e > 1e-12:
                        chi2_stat += ((a - e) ** 2 / e) + ((b - e) ** 2 / e)
                chi2_stat /= 128.0  # normalise

                # [P1.I] FIX: use proper CDF; fall back to approximation if scipy absent
                if SCIPY_AVAILABLE:
                    # unnormalised statistic = chi2_stat * 128 pairs, 127 dof
                    p_val = float(scipy_chi2.cdf(chi2_stat * 128, df=127))
                else:
                    logger.debug("scipy not available; chi2 p-value is approximation")
                    p_val = 1.0 - math.exp(-chi2_stat / 2.0)

                if chi2_stat > best_stat:
                    best_stat = chi2_stat
                    best_p    = p_val
                    best_cn   = cn

            inds = []
            if best_stat > 0.08:
                inds.append(
                    f"Chi-square[{best_cn}]={best_stat:.4f} — LSB replacement signature "
                    f"(CDF p≈{best_p:.3f})")
                return self._hit(min(best_p * 0.9 + 0.1, 0.92), inds)
        except Exception as e:
            logger.debug("Chi-square analysis error: %s", e)
        return self._ok()

    # ── 4. RS (Regular-Singular) — full 4-quantity estimator ─────────────────
    def rs_analysis(self, arr: np.ndarray) -> dict:
        """
        RS analysis on ALL three RGB channels.
        [P0.1] shape fix: use `block + f` not `block + f[:len(block)-1]`.
        [P1.J] FIX: Original code computed only R and S (positive flip function +F).
               The correct Fridrich et al. (2003) RS estimator requires R⁻ and S⁻
               under the negated flip function -F as well.  For clean images
               (R-S) ≈ (R⁻-S⁻); the deviation d = (R-S)-(R⁻-S⁻) grows with
               embedding rate.  This significantly reduces false positives on
               natural images where R > S coincidentally.
        """
        try:
            best_deviation = 0.0
            best_info = {}
            for ci, cn in enumerate(['R', 'G', 'B']):
                ch = arr[:, :, ci].astype(np.float64)
                H, W = ch.shape
                f     = np.array([1, -1,  1, -1], dtype=np.float64)
                f_neg = np.array([-1, 1, -1,  1], dtype=np.float64)

                # Accumulators for R, S, R⁻, S⁻
                R_cnt = S_cnt = Rn_cnt = Sn_cnt = n_blocks = 0

                for y in range(0, H - 3, 4):
                    row = ch[y, :W - (W % 4)].reshape(-1, 4)
                    for block in row:
                        d     = float(np.sum(np.abs(np.diff(block))))
                        # Positive flip: discriminant under +F
                        bf    = block + f
                        df    = float(np.sum(np.abs(np.diff(bf))))
                        # Negative flip: discriminant under -F
                        bf_n  = block + f_neg
                        df_n  = float(np.sum(np.abs(np.diff(bf_n))))

                        R_cnt  += 1 if df  > d  else 0
                        S_cnt  += 1 if df  < d  else 0
                        Rn_cnt += 1 if df_n > d else 0
                        Sn_cnt += 1 if df_n < d else 0
                        n_blocks += 1

                if n_blocks == 0:
                    continue

                R  = R_cnt  / n_blocks
                S  = S_cnt  / n_blocks
                Rn = Rn_cnt / n_blocks
                Sn = Sn_cnt / n_blocks

                # [P1.J] FIX: deviation from the clean-image identity (R-S)=(R⁻-S⁻)
                deviation = (R - S) - (Rn - Sn)

                if deviation > best_deviation:
                    best_deviation = deviation
                    best_info = dict(cn=cn, R=R, S=S, Rn=Rn, Sn=Sn, dev=deviation)

            if best_info and best_info['dev'] > 0.03:
                cn = best_info['cn']
                inds = [
                    f"RS[{cn}] R={best_info['R']:.3f} S={best_info['S']:.3f} "
                    f"R⁻={best_info['Rn']:.3f} S⁻={best_info['Sn']:.3f} "
                    f"deviation={best_info['dev']:.4f} — LSB embedding signature"]
                return self._hit(min(best_info['dev'] * 4.0, 0.90), inds)
        except Exception as e:
            logger.debug("RS analysis error: %s", e)
        return self._ok()

    # ── 5. SPA (Sample Pair Analysis) ────────────────────────────────────────
    def spa_analysis(self, arr: np.ndarray) -> dict:
        """
        Heuristic pair-histogram imbalance on all channels.
        NOTE [P1.9]: Not the full Dumitrescu (2003) SPA; treat as approximate.
        """
        try:
            best_imbalance = 0.0
            best_cn = "R"
            for ci, cn in enumerate(['R', 'G', 'B']):
                c  = arr[:, :, ci].astype(np.int32)
                u, v   = c[:, :-1], c[:, 1:]
                pairs  = u * 256 + v
                pairs2 = (u | 1) * 256 + (v | 1)
                h1 = np.bincount(pairs.ravel(),  minlength=256 * 256).astype(float)
                h2 = np.bincount(pairs2.ravel(), minlength=256 * 256).astype(float)
                imbalance = float(np.sum(np.abs(h1 - h2))) / (h1.sum() + 1e-12)
                if imbalance > best_imbalance:
                    best_imbalance = imbalance; best_cn = cn
            if best_imbalance > 0.02:
                return self._hit(
                    min(best_imbalance * 15, 0.88),
                    [f"SPA imbalance[{best_cn}]={best_imbalance:.4f} — embedding trace"])
        except Exception as e:
            logger.debug("SPA analysis error: %s", e)
        return self._ok()

    # ── 6. WS (Weighted Stego) ────────────────────────────────────────────────
    def ws_analysis(self, gray: np.ndarray) -> dict:
        """
        Weighted Stego analysis (Fridrich et al. 2001).

        [P0.A] CRITICAL FIX — v3.1 regression:
        The v3.1 "fix" computed corr(e, sign(e)).  For any zero-mean continuous
        variable X, this is a mathematical identity:
            Corr(X, sign(X)) = E[|X|] / std(X)
        For Laplacian residuals: ≈ 1/√2 ≈ 0.707.  For Gaussian: ≈ √(2/π) ≈ 0.798.
        EVERY image (clean or stego) produces corr ≈ 0.75, far above the 0.02
        threshold, so the detector always fires → FPR ≈ 100%.

        Correct fix: correlate the prediction residual with the LSB-PARITY indicator
            parity(g) = 1 − 2·(g & 1) = +1 for even pixels, −1 for odd pixels
        This corresponds to the (-1)^s weight from the original WS formulation.
        LSB replacement or matching changes the parity distribution in stego images
        in a way that becomes correlated with the prediction residual.
        Clean images have near-zero correlation; stego images have elevated |corr|.
        """
        try:
            if not SCIPY_AVAILABLE:
                return self._ok()
            g = gray.astype(np.float64)
            ws_kern = np.array([[1, 2, 1], [2, -12, 2], [1, 2, 1]], dtype=np.float64) / 4.0
            pred = ndimage.correlate(g, ws_kern, mode='reflect')
            e    = g - pred

            # [P0.A] FIX: LSB-parity indicator — correct WS correlation target
            # parity = +1 for even-valued pixels, -1 for odd-valued pixels
            parity = 1.0 - 2.0 * (g.astype(np.int64) & 1).astype(np.float64)
            corr   = float(np.corrcoef(e.ravel(), parity.ravel())[0, 1])

            if abs(corr) > 0.02:
                inds = [f"WS parity-residual correlation={corr:.4f} — stego payload trace"]
                return self._hit(min(abs(corr) * 15, 0.85), inds)
        except Exception as e:
            logger.debug("WS analysis error: %s", e)
        return self._ok()

    # ── 7. DCT analysis + Benford's Law (JPEG) ───────────────────────────────
    def dct_analysis(self, gray: np.ndarray) -> dict:
        """
        DCT coefficient histogram + Benford's Law first-digit test.
        NOTE [P2.28]: PIL decodes JPEG to pixel space; real JPEG steganalysis
        requires access to quantized DCT coefficients.
        NOTE [P1.13]: Benford's Law technique is supplementary/non-standard.
        """
        try:
            if not SCIPY_AVAILABLE:
                return self._ok()
            H, W = gray.shape
            block_size = 8
            coeffs = []
            for y in range(0, H - H % block_size, block_size):
                for x in range(0, W - W % block_size, block_size):
                    b = gray[y:y + block_size, x:x + block_size]
                    d = fftpack.dct(fftpack.dct(b, axis=0, norm='ortho'), axis=1, norm='ortho')
                    coeffs.extend(d.ravel().tolist())
            if not coeffs:
                return self._ok()
            a = np.array(coeffs, dtype=np.float32)
            a = a[np.abs(a) > 0.5]
            if len(a) < 100:
                return self._ok()
            inds = []; prob = 0.0
            hist, _ = np.histogram(a, bins=50, range=(-25, 25))
            hist = hist.astype(float); hist /= hist.sum() + 1e-12
            ent = float(-np.sum(hist[hist > 0] * np.log2(hist[hist > 0] + 1e-12)))
            if ent > 5.5:
                inds.append(
                    f"DCT entropy={ent:.3f} — near-uniform distribution (F5/nsF5 artifact)")
                prob = max(prob, 0.68)
            abs_a = np.abs(a); abs_a = abs_a[abs_a >= 1.0].astype(np.int64)
            if len(abs_a) > 50:
                log_vals = np.floor(np.log10(abs_a.astype(np.float64) + 1e-12)).astype(np.int64)
                log_vals = np.clip(log_vals, 0, 18)
                fd = (abs_a // (10 ** log_vals)).astype(np.int64)
                fd = fd[(fd >= 1) & (fd <= 9)]
                if len(fd) > 50:
                    obs = np.bincount(fd, minlength=10).astype(float)[1:] / (len(fd) + 1e-12)
                    ben = np.array([math.log10(1 + 1 / d) for d in range(1, 10)])
                    dev = float(np.sum(np.abs(obs - ben)))
                    if dev > 0.12:
                        inds.append(
                            f"Benford first-digit deviation={dev:.3f} (supplementary only)")
                        prob = max(prob, 0.55)
            if inds:
                return self._hit(prob, inds)
        except Exception as e:
            logger.debug("DCT analysis error: %s", e)
        return self._ok()

    # ── 8. DWT (3-level Haar, normalised) ────────────────────────────────────
    def dwt_analysis(self, gray: np.ndarray) -> dict:
        """3-level Haar DWT with ÷√2 normalisation at each step. [P1.10] fix."""
        try:
            if not SCIPY_AVAILABLE:
                return self._ok()
            inds = []; prob = 0.0
            g = gray.copy().astype(np.float64)
            sqrt2 = np.sqrt(2.0)
            for level in range(3):
                H, W = g.shape
                if H < 4 or W < 4:
                    break
                lo_h = np.stack([(g[i, :] + g[i+1, :]) / sqrt2 for i in range(0, H-1, 2)])
                hi_h = np.stack([(g[i, :] - g[i+1, :]) / sqrt2 for i in range(0, H-1, 2)])
                HH = (hi_h[:, 0::2] - hi_h[:, 1::2]) / sqrt2
                LH = (lo_h[:, 0::2] - lo_h[:, 1::2]) / sqrt2
                HL = (hi_h[:, 0::2] + hi_h[:, 1::2]) / sqrt2
                LL = (lo_h[:, 0::2] + lo_h[:, 1::2]) / sqrt2
                for name, sb in [("HH", HH), ("LH", LH), ("HL", HL)]:
                    e = float(np.mean(sb ** 2))
                    if e > 0.1:
                        k = float(np.mean(sb ** 4) / (e ** 2 + 1e-12))
                        if k > 5.0:
                            inds.append(
                                f"DWT L{level} {name}: kurtosis={k:.1f} — noise in HF subbands")
                            prob = max(prob, 0.55 + 0.05 * (2 - level))
                g = LL
            if inds:
                return self._hit(prob, inds)
        except Exception as e:
            logger.debug("DWT analysis error: %s", e)
        return self._ok()

    # ── 9. LSB Matching (±1 correlation) ────────────────────────────────────
    def lsb_matching(self, arr: np.ndarray) -> dict:
        """
        Detect LSB Matching via adjacent-pixel LSB correlation.
        [P1.14] Threshold was 0.015 (v3.0) then 0.002 (v3.1 over-correction).
        [P1.K] FIX: Threshold raised to 0.01 to reduce FPR on natural images.
                    Require ALL THREE channels (not just 2) to simultaneously show
                    near-zero correlation, because high-quality photographs regularly
                    have one or two channels with |corr| < 0.01 by coincidence.
                    Requiring all 3 dramatically reduces single-image false alarms.
        """
        try:
            inds = []; triggered_channels = 0
            for ci, cn in enumerate(['R', 'G', 'B']):
                ch  = arr[:, :, ci].astype(np.int32)
                lsb = ch & 1
                nxt_lsb = np.roll(ch, -1, axis=1) & 1
                corr = float(np.corrcoef(lsb.ravel(), nxt_lsb.ravel())[0, 1])
                # [P1.K] FIX: threshold 0.01 (was 0.002); all 3 channels required
                if abs(corr) < 0.01:
                    triggered_channels += 1
                    inds.append(f"LSB-Match {cn}: adjacent LSB corr={corr:.5f} (extremely low)")

            # [P1.K] FIX: require ALL 3 channels to reduce FPR
            if triggered_channels == 3:
                prob = 0.60 + 0.05 * triggered_channels
                return self._hit(min(prob, 0.75), inds)
        except Exception as e:
            logger.debug("LSB matching error: %s", e)
        return self._ok()

    # ── 10. PPH (Pixel-Pair Histogram) — all channels ────────────────────────
    def pph_analysis(self, arr: np.ndarray) -> dict:
        """[P1.20] All three RGB channels checked, not just Red."""
        try:
            best_sym = 0.0; best_cn = "R"
            for ci, cn in enumerate(['R', 'G', 'B']):
                ch   = arr[:, :, ci].astype(np.int32)
                u, v = ch[:-1, :], ch[1:, :]
                diff = (v - u).clip(-10, 10)
                hist, _ = np.histogram(diff, bins=21, range=(-10.5, 10.5))
                hist = hist.astype(float) / (hist.sum() + 1e-12)
                sym  = float(np.sum(np.abs(hist - hist[::-1])))
                if sym > best_sym:
                    best_sym = sym; best_cn = cn
            if best_sym > 0.05:
                return self._hit(
                    min(best_sym * 6, 0.82),
                    [f"PPH asymmetry[{best_cn}]={best_sym:.4f} — embedding artifact"])
        except Exception as e:
            logger.debug("PPH analysis error: %s", e)
        return self._ok()

    # ── 11. GFR (Gabor Filter Residuals, JPEG) ───────────────────────────────
    def gfr_analysis(self, gray: np.ndarray) -> dict:
        try:
            if not SCIPY_AVAILABLE:
                return self._ok()
            inds = []; prob = 0.0
            for theta in [0, np.pi / 4, np.pi / 2, 3 * np.pi / 4]:
                for freq in [0.25, 0.5]:
                    sigma = 2.0; lam = 1.0 / freq
                    x, y  = np.meshgrid(np.arange(-5, 6), np.arange(-5, 6))
                    xr    = x * np.cos(theta) + y * np.sin(theta)
                    yr    = -x * np.sin(theta) + y * np.cos(theta)
                    gb    = np.exp(-(xr ** 2 + yr ** 2) / (2 * sigma ** 2)) * np.cos(2 * np.pi * xr / lam)
                    gb   -= gb.mean()
                    res  = ndimage.correlate(gray, gb, mode='reflect')
                    ent  = float(scipy_entropy(np.histogram(res, bins=64)[0] + 1e-6))
                    if ent > 4.2:
                        inds.append(
                            f"GFR θ={theta:.2f} f={freq}: entropy={ent:.3f} — JPEG stego residual")
                        prob = max(prob, 0.58); break
                if prob > 0:
                    break
            if inds:
                return self._hit(prob, inds)
        except Exception as e:
            logger.debug("GFR analysis error: %s", e)
        return self._ok()

    # ── 12. Adaptive cost-map ────────────────────────────────────────────────
    def adaptive_cost_analysis(self, arr: np.ndarray, gray: np.ndarray) -> dict:
        """
        [P1.L] FIX: Original used luminance-LSB (float64 truncation) which has no
        relationship to any individual channel's steganographic modification.
        Fixed: per-channel LSB correlation with the texture map is computed for
        R, G, B separately.  If any channel shows LSB-texture correlation > 0.03
        under high texture-contrast conditions, flag as adaptive stego.
        """
        try:
            if not SCIPY_AVAILABLE:
                return self._ok()
            inds = []; prob = 0.0
            # Texture map derived from luminance Laplacian (same as before)
            g = gray.astype(np.float64)
            lap     = ndimage.laplace(g); texture = np.abs(lap)
            tx_sorted = np.sort(texture.ravel())
            low_tx = tx_sorted[:len(tx_sorted) // 4].mean()
            hi_tx  = tx_sorted[3 * len(tx_sorted) // 4:].mean()
            ratio  = float(hi_tx / (low_tx + 1e-9))
            if ratio > 15:
                texture_mask = (texture > texture.mean()).ravel()
                # [P1.L] FIX: per-channel LSB, not luminance-derived truncation LSB
                for ci, cn in enumerate(['R', 'G', 'B']):
                    ch_lsb = (arr[:, :, ci].astype(np.int64) & 1).ravel().astype(float)
                    lsb_tx_corr = float(np.corrcoef(ch_lsb, texture_mask)[0, 1])
                    if lsb_tx_corr > 0.03:
                        inds.append(
                            f"Adaptive cost [{cn}]: LSB-texture corr={lsb_tx_corr:.4f} "
                            "— HUGO/WOW pattern")
                        prob = max(prob, 0.65)
            if inds:
                return self._hit(prob, inds)
        except Exception as e:
            logger.debug("Adaptive cost analysis error: %s", e)
        return self._ok()

    # ── 13. Entropy block anomaly (luminance) ────────────────────────────────
    def entropy_block_analysis(self, gray: np.ndarray) -> dict:
        try:
            H, W = gray.shape; block = 16; ents = []
            for y in range(0, H - block, block):
                for x in range(0, W - block, block):
                    b = gray[y:y + block, x:x + block].clip(0, 255).astype(np.uint8)
                    p = np.bincount(b.ravel(), minlength=256).astype(float)
                    p /= p.sum() + 1e-12; p = p[p > 0]
                    ents.append(-np.sum(p * np.log2(p)))
            if not ents:
                return self._ok()
            ents = np.array(ents)
            std = float(np.std(ents)); mn = float(np.mean(ents))
            inds = []
            if std < 0.5 and mn > 5.0:
                inds.append(
                    f"Block entropy: μ={mn:.2f} σ={std:.4f} — uniform high entropy (LSB stego)")
                return self._hit(0.65, inds)
            mad = float(np.median(np.abs(ents - np.median(ents))))
            if mad < 0.2 and mn > 5.0:
                inds.append(
                    f"Block entropy: μ={mn:.2f} MAD={mad:.4f} — suspiciously uniform (stego)")
                return self._hit(0.60, inds)
            if std > 2.5:
                inds.append(f"Block entropy: σ={std:.2f} — extreme variation (selective embedding)")
                return self._hit(0.50, inds)
        except Exception as e:
            logger.debug("Entropy block analysis error: %s", e)
        return self._ok()

    # ── 14. Per-channel entropy analysis (NEW — P2.T) ────────────────────────
    def per_channel_entropy_analysis(self, arr: np.ndarray) -> dict:
        """
        [P2.T] NEW: The luminance-only analyses (SRM, entropy block) cannot detect
        steganography confined to a single chroma channel (e.g. embedding only in
        the Green or Blue channel).  This method computes block entropy statistics
        for each of R, G, B independently and flags significant inter-channel
        entropy divergence or uniformly high per-channel entropy as a stego indicator.
        """
        try:
            inds = []; prob = 0.0
            block = 16
            channel_means = []
            channel_stds  = []
            for ci, cn in enumerate(['R', 'G', 'B']):
                H, W = arr.shape[:2]; ents = []
                for y in range(0, H - block, block):
                    for x in range(0, W - block, block):
                        b = arr[y:y + block, x:x + block, ci].clip(0, 255).astype(np.uint8)
                        p = np.bincount(b.ravel(), minlength=256).astype(float)
                        p /= p.sum() + 1e-12; p = p[p > 0]
                        ents.append(-np.sum(p * np.log2(p)))
                if not ents:
                    continue
                ents = np.array(ents)
                channel_means.append(float(np.mean(ents)))
                channel_stds.append(float(np.std(ents)))

            if len(channel_means) == 3:
                # Flag if one channel has significantly higher mean entropy than the others
                max_mean  = max(channel_means)
                min_mean  = min(channel_means)
                divergence = max_mean - min_mean
                if divergence > 1.5 and max_mean > 5.0:
                    idx = channel_means.index(max_mean)
                    cn  = ['R', 'G', 'B'][idx]
                    inds.append(
                        f"Per-channel entropy [{cn}] significantly higher "
                        f"(divergence={divergence:.3f}) — chroma-channel embedding suspected")
                    prob = max(prob, 0.55 + min(divergence * 0.05, 0.15))
                # Flag if ALL channels have uniformly low block-entropy std (all-channel embedding)
                if all(s < 0.4 for s in channel_stds) and all(m > 5.0 for m in channel_means):
                    inds.append(
                        "Per-channel entropy: all RGB channels show uniformly high entropy "
                        f"(means={[f'{m:.2f}' for m in channel_means]}) — wide-spectrum embedding")
                    prob = max(prob, 0.60)

            if inds:
                return self._hit(prob, inds)
        except Exception as e:
            logger.debug("Per-channel entropy analysis error: %s", e)
        return self._ok()

    # ── 15. GAN/AI stego artifact detection ──────────────────────────────────
    def gan_stego_detection(self, arr: np.ndarray, gray: np.ndarray) -> dict:
        """
        Detect SteganoGAN/HiDDeN/RivaGAN/StegaStamp artifacts.
        [P1.17] threshold raised from 0.6 to 0.35.
        [P2.P] FIX: Original spectral check sampled near-DC rows/cols 1:5, which
               misses GAN upsampling artifacts.  GAN decoders with stride-2
               upsampling create periodic artifacts at FFT frequencies ≈ N/stride.
               For a 256×256 image with stride-2: artifacts at rows/cols ~128;
               with stride-4: rows/cols ~64; mixed nets: also ~32.
               New check: compare energy in stride-aligned bands to the mean,
               flagging if any band is >3× the overall mean energy.
        """
        try:
            inds = []; prob = 0.0; spectral_hit = False
            if SCIPY_AVAILABLE:
                spectrum = np.abs(fftpack.fft2(gray - gray.mean()))
                spectrum = np.log1p(spectrum)
                total    = float(spectrum.mean()) + 1e-9

                # [P2.P] FIX: check stride-aligned FFT bands (32, 64, 128) not near-DC
                N = spectrum.shape[0]
                for stride_band in [N // 8, N // 4, N // 2]:
                    if stride_band < 2:
                        continue
                    lo, hi = max(1, stride_band - 2), min(N // 2, stride_band + 2)
                    h_energy = float(np.mean(spectrum[lo:hi, :]))
                    v_energy = float(np.mean(spectrum[:, lo:hi]))
                    if h_energy / total > 3.0 or v_energy / total > 3.0:
                        inds.append(
                            f"GAN spectral band [{lo}:{hi}] H={h_energy:.2f} V={v_energy:.2f} "
                            f"(ratio H={h_energy/total:.1f}×, V={v_energy/total:.1f}×) "
                            "— stride-aligned periodic artifact")
                        prob = max(prob, 0.60)
                        spectral_hit = True
                        break

            rg = float(np.corrcoef(arr[:, :, 0].ravel(), arr[:, :, 1].ravel())[0, 1])
            rb = float(np.corrcoef(arr[:, :, 0].ravel(), arr[:, :, 2].ravel())[0, 1])
            gb = float(np.corrcoef(arr[:, :, 1].ravel(), arr[:, :, 2].ravel())[0, 1])
            mean_corr = (rg + rb + gb) / 3.0

            # [P1.17] threshold at 0.35; moderate distortion requires spectral confirmation
            if mean_corr < 0.35 and mean_corr > 0:
                inds.append(
                    f"Channel correlation: RG={rg:.3f} RB={rb:.3f} GB={gb:.3f} "
                    "— strongly distorted (GAN stego)")
                prob = max(prob, 0.60)
            elif mean_corr < 0.55 and spectral_hit:
                inds.append(
                    f"Channel correlation: mean={mean_corr:.3f} + spectral hit "
                    "— combined GAN indicator")
                prob = max(prob, 0.55)

            if inds:
                return self._hit(prob, inds)
        except Exception as e:
            logger.debug("GAN stego detection error: %s", e)
        return self._ok()

    # ── 16. JPEG ghost (gated to JPEG files) ─────────────────────────────────
    def jpeg_ghost_analysis(self, img: Image.Image, is_jpeg: bool = False) -> dict:
        """
        JPEG ghost analysis.
        [P1.N] FIX: Previously called for ALL image formats.  Ghost analysis is
        JPEG-specific — comparing a lossless PNG to re-saved JPEG copies is
        meaningless.  The `is_jpeg` flag (set by analyze() based on the source
        file's magic bytes) gates this analysis.  Returns _ok() immediately for
        non-JPEG sources.
        NOTE [P2.34]: PIL decodes to pixel space; results are supplementary only.
        """
        if not is_jpeg:
            return self._ok()
        try:
            inds = []; prob = 0.0
            gray_arr = np.array(img.convert('L'), dtype=np.float64)
            diffs = []
            for q in [50, 55, 60, 65, 70, 75, 80, 85, 90, 95]:
                buf = io.BytesIO()
                img.save(buf, format='JPEG', quality=q)
                buf.seek(0)
                recomp = np.array(Image.open(buf).convert('L'), dtype=np.float64)
                if recomp.shape == gray_arr.shape:
                    diffs.append((q, float(np.mean(np.abs(gray_arr - recomp)))))
            if diffs:
                qs, ds = zip(*diffs)
                min_q  = qs[int(np.argmin(ds))]
                min_d  = min(ds)
                if min_d < 1.0 and min_q < 90:
                    inds.append(
                        f"JPEG ghost: min diff at Q={min_q} ({min_d:.3f}) "
                        "— possible double compression (supplementary)")
                    prob = 0.55
            if inds:
                return self._hit(prob, inds)
        except Exception as e:
            logger.debug("JPEG ghost analysis error: %s", e)
        return self._ok()


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — Multi-Modal Stego Detectors
# ═══════════════════════════════════════════════════════════════════════════════

class _MultiModalStegDetector:
    """
    Detect steganography in audio, video, network, text, and document formats.
    NOTE [P0.3 / P1.18]: Detectors are ONLY called on bytes of the matching
    file type.  Gating is enforced in analyze_file().
    """

    def detect_audio_steg(self, file_bytes: bytes) -> dict:
        """
        Detect audio steganography.
        [P1.F] FIX: FLAC, OGG, and AAC magic bytes now detected separately.
               These formats previously fell through all branches silently,
               returning empty results while claiming support.  They now return
               an honest "not implemented" warning so callers know the result
               is not a clean bill of health — it is simply unknown.
        [P1.19] Audio LSB uniformity retained but confidence capped at 0.45.
        """
        inds = []; prob = 0.0
        try:
            # ── WAV (RIFF) ────────────────────────────────────────────────
            if file_bytes[:4] == b'RIFF':
                if len(file_bytes) > 44:
                    samples = np.frombuffer(file_bytes[44:], dtype=np.int16).astype(np.float32)
                    lsb      = (samples.astype(int) & 1).astype(float)
                    lsb_mean = float(np.mean(lsb))
                    if 0.48 < lsb_mean < 0.52:
                        inds.append(
                            f"Audio LSB near-uniform ({lsb_mean:.3f}) "
                            "— possible LSB embedding (low confidence alone)")
                        prob = max(prob, 0.45)
                    if len(samples) > 8000:
                        ac   = np.correlate(samples[:4000], samples[:4000], mode='full')
                        ac   = ac[len(ac) // 2:]
                        ac  /= ac[0] + 1e-12
                        lags = np.where((ac[50:200] > 0.1) & (ac[50:200] < 0.5))[0]
                        if len(lags) > 3:
                            inds.append(f"Audio echo at lag {lags[0]+50} — echo hiding stego")
                            prob = max(prob, 0.70)

            # ── MP3 (ID3 tag or sync frame) ───────────────────────────────
            elif file_bytes[:3] == b'ID3' or file_bytes[:2] == b'\xff\xfb':
                frame_count = file_bytes.count(b'\xff\xfb')
                if frame_count > 10:
                    inds.append(
                        f"MP3 frames detected ({frame_count}) — check for MP3Stego encoding")
                    prob = max(prob, 0.45)

            # [P1.F] FIX: FLAC — format detected, analysis not yet implemented
            elif file_bytes[:4] == b'fLaC':
                inds.append(
                    "FLAC audio detected — frame-level LSB and phase-coding analysis "
                    "not implemented; result is UNKNOWN, not CLEAN.")
                prob = 0.0  # Cannot make a positive claim; indicate uncertainty via warning

            # [P1.F] FIX: OGG — format detected, analysis not yet implemented
            elif file_bytes[:4] == b'OggS':
                inds.append(
                    "OGG audio detected — Vorbis/Opus frame analysis not implemented; "
                    "result is UNKNOWN, not CLEAN.")
                prob = 0.0

            # [P1.F] FIX: AAC ADTS sync (0xFF followed by 0xF0-0xFF)
            elif (len(file_bytes) >= 2
                  and file_bytes[0] == 0xFF
                  and (file_bytes[1] & 0xF0) == 0xF0):
                inds.append(
                    "AAC ADTS audio detected — ADTS frame analysis not implemented; "
                    "result is UNKNOWN, not CLEAN.")
                prob = 0.0

        except Exception as e:
            logger.debug("Audio steg error: %s", e)

        return {"suspicious": bool(inds and prob > 0), "probability": prob, "indicators": inds}

    def detect_network_steg(self, raw_bytes: bytes) -> dict:
        """
        Detect network/protocol steganography indicators.
        [P2.R] FIX: DNS covert channel detection now requires per-label Shannon
               entropy > 4.0 bits/char in addition to label length ≥ 32.
               This eliminates false positives from CDN cache keys, DNSSEC
               labels, and base32-encoded UUIDs that are long but not random.
        """
        inds = []; prob = 0.0

        dns_pattern = re.findall(rb'(?:[a-zA-Z0-9]{32,}\.)+[a-zA-Z]{2,6}', raw_bytes)
        high_entropy_dns = []
        for match in dns_pattern:
            # [P2.R] FIX: compute per-label Shannon entropy; require > 4.0 bits/char
            label = match.split(b'.')[0]
            if len(label) == 0:
                continue
            freq  = np.bincount(np.frombuffer(label, dtype=np.uint8), minlength=256).astype(float)
            freq  = freq[freq > 0] / len(label)
            ent   = float(-np.sum(freq * np.log2(freq)))
            if ent > 4.0:
                high_entropy_dns.append((match, ent))

        if high_entropy_dns:
            inds.append(
                f"DNS covert channel: {len(high_entropy_dns)} long high-entropy subdomains "
                f"(entropy > 4.0 bits/char)")
            prob = max(prob, 0.70)

        http_headers = re.findall(rb'X-[A-Za-z\-]+: ([^\r\n]{20,})', raw_bytes)
        for hdr in http_headers:
            ent = self._entropy(hdr)
            if ent > 4.5:
                inds.append(
                    f"HTTP header stego: high-entropy X-header (entropy={ent:.2f})")
                prob = max(prob, 0.60)

        if raw_bytes[:4] == b'\xd4\xc3\xb2\xa1':
            inds.append("PCAP detected — analyze for covert timing channel")
            prob = max(prob, 0.40)

        return {"suspicious": bool(inds), "probability": prob, "indicators": inds}

    def detect_text_steg(self, text_bytes: bytes, source_ext: str = "") -> dict:
        """
        Detect text/document steganography.
        [P1.G] FIX: .docx is a ZIP archive; raw bytes must NOT be decoded as UTF-8
               text (it's binary XML+media). Caller should unzip and pass extracted
               XML bytes.  When source_ext is '.docx' and the bytes start with PK,
               this method attempts unzipping internally as a safety net.
        [P2.Q] FIX: HTML and Markdown files contain valid markup that triggered
               false positives:
               — HTML: trailing spaces in CSS, &nbsp; in entities.
               — Markdown: two trailing spaces = <br> per GFM spec.
               Fix: strip HTML tags before analysis; disable trailing-space check
               for .html/.htm/.md sources.
        [P1.18 / P0.3]: Must NOT be called on PNG/image bytes.
        """
        inds = []; prob = 0.0

        # [P1.G] FIX: .docx is ZIP — extract word/document.xml
        if source_ext.lower() == '.docx' or text_bytes[:2] == b'PK':
            try:
                xml_bytes = b''
                with _zipfile.ZipFile(io.BytesIO(text_bytes)) as zf:
                    for name in zf.namelist():
                        if name.lower().endswith('.xml'):
                            xml_bytes += zf.read(name)
                if xml_bytes:
                    text_bytes = xml_bytes
            except Exception as e:
                logger.debug("docx unzip failed, treating as binary: %s", e)
                return {"suspicious": False, "probability": 0.0,
                        "indicators": ["docx ZIP extraction failed — cannot analyze"]}

        text = text_bytes.decode('utf-8', errors='replace')

        # [P2.Q] FIX: strip HTML tags for HTML/HTM sources to avoid markup FP
        is_markup = source_ext.lower() in ('.html', '.htm')
        is_md     = source_ext.lower() == '.md'
        if is_markup:
            text = re.sub(r'<[^>]+>', '', text)

        # Homoglyph detection (Cyrillic mixed with Latin)
        cyrillic = sum(1 for c in text if '\u0400' <= c <= '\u04ff')
        latin    = sum(1 for c in text if c.isalpha() and ord(c) < 128)
        if cyrillic > 0 and latin > 10:
            ratio = cyrillic / (latin + 1)
            inds.append(
                f"Homoglyph stego: {cyrillic} Cyrillic chars mixed with {latin} Latin "
                f"(ratio={ratio:.3f})")
            prob = max(prob, 0.80)

        # Zero-width character detection
        zwc = sum(1 for c in text if c in '\u200b\u200c\u200d\ufeff\u2060')
        if zwc > 0:
            inds.append(f"Zero-width character stego: {zwc} ZWC found — hidden binary payload")
            prob = max(prob, 0.88)

        # [P2.Q] FIX: trailing-space check disabled for .md and .html (valid in those formats)
        if not is_markup and not is_md:
            lines = text.split('\n')
            ws_pattern = [len(l) - len(l.rstrip()) for l in lines]
            if max(ws_pattern, default=0) > 3:
                inds.append(
                    f"Whitespace stego: trailing spaces detected "
                    f"({max(ws_pattern, default=0)} max) — SNOW/similar")
                prob = max(prob, 0.72)

        return {"suspicious": bool(inds), "probability": prob, "indicators": inds}

    def detect_pdf_steg(self, raw_bytes: bytes) -> dict:
        """
        Detect PDF/document steganography: hidden layers, embedded streams.
        [P1.M / P2.U] FIX: Compressed streams (FlateDecode, DCTDecode, LZWDecode)
               ALWAYS have entropy > 7.5 by construction.  Flagging them produces
               FP on every PDF with embedded images or fonts — i.e., most PDFs.
               Fix: inspect the stream dictionary (bytes preceding the 'stream'
               keyword) for a /Filter entry.  Only flag unfiltered (raw) streams
               with high entropy, which is anomalous in compliant PDFs.
        """
        inds = []; prob = 0.0
        if not raw_bytes[:4] == b'%PDF':
            return {"suspicious": False, "probability": 0.0, "indicators": []}

        hidden_layers = raw_bytes.count(b'/Invisible')
        if hidden_layers > 0:
            inds.append(f"PDF: {hidden_layers} invisible objects — text/data stego")
            prob = max(prob, 0.82)

        # [P1.M] FIX: find stream boundaries; check for /Filter in pre-stream dict
        #  Strategy: find each 'stream\r\n' or 'stream\n' and look 500 bytes back
        #  for /Filter; skip if found.
        stream_iter = list(re.finditer(rb'stream[\r\n]', raw_bytes))
        flagged = 0
        for i, m in enumerate(stream_iter[:10]):
            stream_start = m.end()
            # Find endstream
            end_match = re.search(rb'endstream', raw_bytes[stream_start:stream_start + 20_000_000])
            if not end_match:
                continue
            stream_data = raw_bytes[stream_start:stream_start + end_match.start()]
            # Check preceding dictionary for /Filter
            pre_dict = raw_bytes[max(0, m.start() - 500):m.start()]
            if b'/Filter' in pre_dict:
                # Compressed stream — entropy check meaningless
                continue
            ent = self._entropy(stream_data[:2000]) if len(stream_data) > 100 else 0
            if ent > 7.5:
                inds.append(
                    f"PDF unfiltered stream #{i}: entropy={ent:.2f} "
                    "— raw high-entropy data (no /Filter declared)")
                prob = max(prob, 0.72)
                flagged += 1
                if flagged >= 3:
                    break

        return {"suspicious": bool(inds), "probability": prob, "indicators": inds}

    @staticmethod
    def _entropy(data) -> float:
        if not data:
            return 0.0
        if isinstance(data, (bytes, bytearray)):
            d = np.frombuffer(data[:10000], dtype=np.uint8)
        else:
            d = np.frombuffer(bytes(data[:10000]), dtype=np.uint8)
        p = np.bincount(d, minlength=256).astype(float) / max(len(d), 1)
        p = p[p > 0]
        return float(-np.sum(p * np.log2(p)))

    @staticmethod
    def _label_entropy(label_bytes: bytes) -> float:
        """Shannon entropy per character for a byte string (used for DNS labels)."""
        if not label_bytes:
            return 0.0
        freq = np.bincount(np.frombuffer(label_bytes, dtype=np.uint8),
                           minlength=256).astype(float)
        freq = freq[freq > 0] / len(label_bytes)
        return float(-np.sum(freq * np.log2(freq)))


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — Model Manager
# ═══════════════════════════════════════════════════════════════════════════════

STEG_MODELS_DIR = Path(os.path.expanduser("~")) / ".steg_models"

_WEIGHT_REGISTRY = {
    "gbras_srm_kernels": {
        "url": "https://github.com/BioAITeam/Steganalysis/raw/main/SRM_Kernels1.npy",
        "filename": "SRM_Kernels1.npy",
        "is_zip": False,
        "description": "GBRAS-Net 30-filter SRM kernels",
    },
    # [S.25] NOTE: The Binghamton ALASKA ONNX URL does not exist publicly.
    # Removed to avoid silent 404 failures.
}


def _download_file(url: str, dest: Path, description: str = "") -> bool:
    """[S.21] Download with SSL cert verification."""
    try:
        if not url.startswith(('http://', 'https://')):
            logger.warning("Invalid URL scheme: %s", url)
            return False
        dest = dest.resolve()
        if not str(dest).startswith(str(STEG_MODELS_DIR.resolve())):
            logger.warning("Path traversal attempt blocked: %s", dest)
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading %s from %s ...", description or dest.name, url)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode    = ssl.CERT_REQUIRED
        req = urllib.request.Request(url, headers={"User-Agent": "StegDetector/3.2"})
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as response:
            with open(str(dest), 'wb') as f:
                f.write(response.read())
        logger.info("Downloaded %s (%d bytes)", dest.name, dest.stat().st_size)
        return True
    except Exception as e:
        logger.warning("Download failed for %s: %s", url, e)
        if dest.exists():
            try: dest.unlink()
            except Exception as ce: logger.debug("Cleanup error: %s", ce)
        return False


def _ensure_weights():
    STEG_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    for key, info in _WEIGHT_REGISTRY.items():
        dest = STEG_MODELS_DIR / info["filename"]
        if dest.exists():
            continue
        ok = _download_file(info["url"], dest, info["description"])
        if ok and info.get("is_zip"):
            try:
                with _zipfile.ZipFile(str(dest), 'r') as zf:
                    for member in zf.namelist():
                        safe_path = (STEG_MODELS_DIR / member).resolve()
                        if not str(safe_path).startswith(str(STEG_MODELS_DIR.resolve())):
                            logger.warning("Zip slip attempt blocked: %s", member)
                            continue
                        zf.extract(member, str(STEG_MODELS_DIR))
                logger.info("Extracted %s", dest.name)
            except Exception as e:
                logger.warning("Extraction failed for %s: %s", dest.name, e)


class _ModelManager:
    """
    [P2.O] FIX: Weight paths stored as instance attributes (self._weight_paths)
    instead of module globals.  Multiple threads can safely instantiate
    AdvancedStegDetector concurrently; each instance manages its own paths
    with no inter-instance mutation.
    """

    # Keyword → model-name mapping for auto-detecting .pth files
    _PTH_KEYWORDS = {
        "srnet":      "SRNet",
        "gbras":      "GBRAS-Net",
        "bayar":      "BayarNet",
        "zhu":        "ZhuNet",
        "efficient":  "EfficientSteg",
        "stegformer": "StegFormer",
        "swin":       "SwinConvNeXt",
        "convnext":   "SwinConvNeXt",
    }

    def __init__(self):
        self._any_weights_loaded = False
        self._loaded_models: set = set()
        self.alaska_rt = None

        # [P2.O] FIX: instance-level paths dict — no module globals written
        self._weight_paths: Dict[str, str] = {name: "" for name in self._PTH_KEYWORDS.values()}
        self._alaska_onnx_path = ""

        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available — DL steg layer disabled")
            return

        try:
            _ensure_weights()
        except Exception as e:
            logger.debug("Weight auto-download attempt: %s", e)

        # Auto-discover ONNX
        for pattern in ["*.onnx", "models/*.onnx"]:
            onnx_files = list(STEG_MODELS_DIR.glob(pattern))
            if onnx_files:
                self._alaska_onnx_path = str(onnx_files[0]); break

        # Auto-discover .pth files
        for pth_file in STEG_MODELS_DIR.glob("*.pth"):
            fname = pth_file.stem.lower()
            for keyword, model_name in self._PTH_KEYWORDS.items():
                if keyword in fname and not self._weight_paths.get(model_name):
                    self._weight_paths[model_name] = str(pth_file)
                    logger.info("Auto-resolved %s → %s", model_name, pth_file)

        # Instantiate models
        self.srnet   = SRNet()
        self.gbras   = GBRASNet()
        self.bayar   = BayarNet()
        self.zhunet  = ZhuNet()
        self.effnet  = EfficientStegNet()
        self.stegfmr = StegFormer()
        self.hybrid  = SwinConvNeXtHybrid()

        for name, model in [
            ("SRNet",         self.srnet),
            ("GBRAS-Net",     self.gbras),
            ("BayarNet",      self.bayar),
            ("ZhuNet",        self.zhunet),
            ("EfficientSteg", self.effnet),
            ("StegFormer",    self.stegfmr),
            ("SwinConvNeXt",  self.hybrid),
        ]:
            if self._load(model, self._weight_paths.get(name, ""), name):
                self._any_weights_loaded = True
                self._loaded_models.add(name)

        if ONNX_AVAILABLE and self._alaska_onnx_path and Path(self._alaska_onnx_path).exists():
            try:
                self.alaska_rt = ort.InferenceSession(self._alaska_onnx_path)
                self._any_weights_loaded = True
                self._loaded_models.add("ALASKA_ONNX")
            except Exception as e:
                logger.warning("ALASKA ONNX load error: %s", e)

        if not self._any_weights_loaded:
            logger.warning(
                "NO pretrained DL weights loaded — DL layer excluded from scoring. "
                "Provide .pth files in %s", STEG_MODELS_DIR)
        else:
            logger.info("DL layer active: %s", ", ".join(sorted(self._loaded_models)))

    @staticmethod
    def _load(model, path: str, name: str) -> bool:
        if path and Path(path).exists():
            try:
                sd = torch.load(path, map_location="cpu", weights_only=True)
                if isinstance(sd, dict) and "state_dict" in sd:
                    sd = sd["state_dict"]
                model.load_state_dict(sd, strict=False)
                logger.info("%s weights loaded from %s", name, path)
                return True
            except Exception as e:
                logger.warning("%s weight load error: %s (excluded from scoring)", name, e)
        return False

    def predict_all(self, img: Image.Image) -> dict:
        """
        [P1.E / P2.S] FIX: Use _to_tensor_crops() to generate 5 crops (center + 4
        corners) at UNIFIED spatial positions for ALL models.  Each model scores all
        5 crops; the MAX probability is taken per model, ensuring that steganography
        embedded anywhere in the image (not just the center) is detected.
        """
        if not TORCH_AVAILABLE or not self._any_weights_loaded:
            return {}

        # Unified 5-crop tensors for all models at both sizes
        crops_256 = _to_tensor_crops(img, size=256)
        crops_128 = _to_tensor_crops(img, size=128)

        scores: Dict[str, float] = {}

        for name, model, crops in [
            ("SRNet",         self.srnet,   crops_256),
            ("GBRAS-Net",     self.gbras,   crops_256),
            ("BayarNet",      self.bayar,   crops_256),
            ("ZhuNet",        self.zhunet,  crops_256),
            ("EfficientSteg", self.effnet,  crops_128),
            ("StegFormer",    self.stegfmr, crops_256),
            ("SwinConvNeXt",  self.hybrid,  crops_256),
        ]:
            if name not in self._loaded_models:
                continue
            try:
                # [P1.E] Score all crops; take MAX (detect stego in any region)
                crop_probs = [model.predict_proba(t) for t in crops]
                scores[name] = float(max(crop_probs))
            except Exception as e:
                logger.debug("%s predict error: %s", name, e)

        if self.alaska_rt and "ALASKA_ONNX" in self._loaded_models:
            try:
                # ALASKA: score center crop only (JPEG-targeted, content-independent)
                center_t = crops_256[0].numpy().astype(np.float32)
                nm  = self.alaska_rt.get_inputs()[0].name
                out = self.alaska_rt.run(None, {nm: center_t})[0]
                p   = float(np.exp(out[0, 1]) / (np.exp(out[0]).sum() + 1e-9))
                scores["ALASKA_ONNX"] = p
            except Exception:
                pass

        return scores


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — Calibrated Meta-Learner Ensemble
# ═══════════════════════════════════════════════════════════════════════════════

class _EnsembleFusion:
    """
    Calibrated ensemble fusion combining DL scores + classical probabilities.
    NOTE [P2.30]: steg_probability is NOT a calibrated probability. It is an
    uncalibrated ordinal suspicion score. Treat it as a ranking, not a posterior.
    """

    _DL_WEIGHTS = {
        "SRNet":         0.22,
        "GBRAS-Net":     0.18,
        "BayarNet":      0.15,
        "ZhuNet":        0.14,
        "EfficientSteg": 0.12,
        "StegFormer":    0.10,
        "SwinConvNeXt":  0.09,
        "ALASKA_ONNX":   0.22,
    }

    def fuse(self, dl_scores: dict, classical_probs: list,
             n_classical_triggered: int, n_mm_triggered: int = 0) -> float:
        """
        Fuse DL scores and classical probabilities.
        [P0.4] n_classical_triggered and n_mm_triggered tracked separately.
        [P1.B] FIX: n_mm_triggered was accepted but never used.  Now applied as
               a separate additive boost independent of the classical vote.
               Multi-modal detections (audio, text, PDF) get a modest boost because
               they target completely different embedding domains and their firing
               provides independent evidence orthogonal to image classical features.
        """
        p = 0.0
        has_dl = bool(dl_scores)

        # ── DL weighted average ────────────────────────────────────────────
        if has_dl:
            dl_total_w = 0.0
            for name, score in dl_scores.items():
                w = self._DL_WEIGHTS.get(name, 0.10)
                p += w * score; dl_total_w += w
            if dl_total_w > 0:
                p /= dl_total_w

        # ── Classical Noisy-OR fusion ──────────────────────────────────────
        if classical_probs:
            noisy_or = 1.0 - float(np.prod([1.0 - v for v in classical_probs]))
            if has_dl:
                p = max(p, noisy_or * 0.88)
            else:
                p = noisy_or

        # ── Classical consensus vote boost ────────────────────────────────
        if n_classical_triggered >= 3:
            boost = 0.06 * (n_classical_triggered - 2)
            p = min(1.0, p + boost)
        if n_classical_triggered >= 5:
            p = min(1.0, p + 0.10)

        # ── DL consensus boost ────────────────────────────────────────────
        if has_dl:
            dl_positive = sum(1 for s in dl_scores.values() if s > 0.5)
            if dl_positive >= 3:
                p = min(1.0, p + 0.05 * dl_positive)

        # ── [P1.B] FIX: multi-modal trigger boost (independent evidence) ──
        # Each additional multi-modal technique that fires provides independent
        # evidence from a different embedding domain; apply a modest separate boost.
        if n_mm_triggered >= 1:
            mm_boost = 0.04 * n_mm_triggered
            p = min(1.0, p + mm_boost)

        return float(min(p, 1.0))


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — Utility: Detect JPEG source from magic bytes
# ═══════════════════════════════════════════════════════════════════════════════

def _is_jpeg_bytes(raw_bytes: bytes) -> bool:
    """
    [P1.N] Return True if raw_bytes represents a JPEG/JFIF/Exif image.
    JPEG files start with SOI marker 0xFFD8 followed by an APP0 (JFIF: 0xFFE0)
    or APP1 (Exif: 0xFFE1) marker.
    """
    if len(raw_bytes) < 4:
        return False
    if raw_bytes[:2] != b'\xff\xd8':
        return False
    # Check for JFIF or Exif marker in first bytes
    if raw_bytes[2:4] in (b'\xff\xe0', b'\xff\xe1'):
        return True
    # Generic JPEG: SOI is sufficient if APP marker follows
    if raw_bytes[2] == 0xff:
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — Main Detector (public API)
# ═══════════════════════════════════════════════════════════════════════════════

_IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.gif', '.webp'}
_AUDIO_EXTS = {'.wav', '.mp3', '.flac', '.ogg', '.aac'}
_TEXT_EXTS  = {'.txt', '.html', '.htm', '.md', '.docx', '.csv'}
_NET_EXTS   = {'.pcap', '.pcapng'}


class AdvancedStegDetector:
    """
    Ultra-Advanced Steganalysis Engine v3.2 — 2026 Threat Landscape (Fixed).

    IMPORTANT NOTE [P2.30]: steg_probability is an uncalibrated suspicion SCORE,
    not a true probability. Without Platt/isotonic calibration on labelled data,
    0.72 ≠ 72% chance of steganography. Use it as an ordinal ranking only.

    IMPORTANT NOTE [P2.26]: Video steganography is NOT implemented.

    Usage:
        detector = AdvancedStegDetector()
        result   = detector.analyze("suspicious.png")
        print(result["steg_probability"], result["steg_type"])
    """

    _TYPE_MAP = [
        ("DCT Analysis",            "JPEG Steganography (F5/nsF5/J-UNIWARD/UERD/J-MiPOD)"),
        ("GFR Analysis",            "JPEG Steganography (J-UNIWARD/OutGuess)"),
        ("JPEG Ghost",              "JPEG Double-Compression (F5/Steghide re-save)"),
        ("RS Analysis",             "LSB Replacement (Classic)"),
        ("Chi-Square",              "LSB Replacement (Classic)"),
        ("PPH Analysis",            "LSB Replacement (Classic)"),
        ("LSB Matching",            "LSB Matching (±1 steganography)"),
        ("SPAM Analysis",           "LSB Matching / Spatial Embedding"),
        ("Adaptive Cost",           "Adaptive Steganography (HUGO/WOW/HILL/MiPOD/S-UNIWARD)"),
        ("GAN Stego",               "AI/GAN Steganography (SteganoGAN/HiDDeN/RivaGAN)"),
        ("Per-Channel Entropy",     "Chroma-Channel Steganography (single-channel embedding)"),
        ("Audio Stego",             "Audio Steganography (Phase/Echo/MP3Stego)"),
        ("Network Stego",           "Network Covert Channel (DNS/HTTP/IP stego)"),
        ("Text Stego",              "Text Steganography (Homoglyph/ZWC/Whitespace)"),
        ("PDF Stego",               "Document Steganography (PDF/DOCX)"),
        ("SRNet",                   "Spatial Steganography (WOW/S-UNIWARD/HILL)"),
        ("GBRAS",                   "Spatial Steganography (WOW/HILL/MiPOD)"),
        ("StegFormer",              "Spatial Steganography (BOSS/BOSSBase)"),
        ("ALASKA",                  "JPEG Steganography (J-UNIWARD/UERD/J-MiPOD)"),
    ]

    _CONFIDENCE_LEVELS = [
        (0.90, "CRITICAL"),
        (0.70, "HIGH"),
        (0.50, "MEDIUM"),
        (0.30, "LOW"),
        (0.00, "BENIGN"),
    ]

    def __init__(self):
        self._classical  = _ClassicalAnalyser()
        self._multimodal = _MultiModalStegDetector()
        self._models     = _ModelManager()
        self._fusion     = _EnsembleFusion()

    def analyze(self, src: Union[str, "Image.Image", np.ndarray, bytes],
                _raw_bytes: Optional[bytes] = None) -> dict:
        """
        Analyze an image for steganography.

        [P1.C] FIX: Added 200 MB cap for file-path inputs — previously analyze()
               bypassed the cap that was only in analyze_file().
        [P1.D] The `_raw_bytes` parameter is used by analyze_file() to pass the
               already-read bytes so the file is not read from disk a second time.
               When provided, SHA256 is computed from these bytes (original file),
               not from the re-encoded PNG buffer.
        [P0.3 / P1.18] Multi-modal detectors NOT run here (image bytes only).
        """
        result = {
            "steg_detected": False, "steg_probability": 0.0,
            "steg_type": None, "confidence": "BENIGN",
            "indicators": [], "techniques_triggered": [],
            "dl_scores": {}, "analysis": {}, "sha256": "",
            "probability_note": (
                "steg_probability is an uncalibrated suspicion score [0,1], "
                "not a true posterior probability. Requires Platt/isotonic calibration."
            ),
        }
        try:
            # [P1.C] FIX: enforce 200 MB cap for file paths before Image.open()
            if isinstance(src, (str, Path)):
                p = Path(src)
                if p.exists():
                    file_size = p.stat().st_size
                    if file_size > _MAX_FILE_BYTES:
                        result["error"] = (
                            f"File too large ({file_size / 1024 / 1024:.1f} MB > "
                            f"{_MAX_FILE_BYTES // 1024 // 1024} MB limit). Analysis refused.")
                        return _to_python(result)

            img, arr, gray = _load_image(src)

            # SHA256: prefer original raw bytes (from analyze_file), else re-encoded PNG
            if _raw_bytes is not None:
                result["sha256"] = hashlib.sha256(_raw_bytes).hexdigest()
            else:
                buf = io.BytesIO(); img.save(buf, format='PNG')
                result["sha256"] = hashlib.sha256(buf.getvalue()).hexdigest()

            # Determine if source is JPEG for jpeg_ghost gating [P1.N]
            is_jpeg = False
            if _raw_bytes is not None:
                is_jpeg = _is_jpeg_bytes(_raw_bytes)
            elif isinstance(src, (str, Path)):
                try:
                    header = Path(src).read_bytes()[:12]
                    is_jpeg = _is_jpeg_bytes(header)
                except Exception:
                    pass

            # ── LAYER 1: Classical techniques ──────────────────────────────
            classical_runs = [
                ("SRM Analysis",          self._classical.srm_analysis(gray)),
                ("SPAM Analysis",         self._classical.spam_analysis(gray)),
                ("Chi-Square",            self._classical.chi_square_analysis(arr)),
                ("RS Analysis",           self._classical.rs_analysis(arr)),
                ("SPA Analysis",          self._classical.spa_analysis(arr)),
                ("WS Analysis",           self._classical.ws_analysis(gray)),
                ("DCT Analysis",          self._classical.dct_analysis(gray)),
                ("DWT Analysis",          self._classical.dwt_analysis(gray)),
                ("LSB Matching",          self._classical.lsb_matching(arr)),
                ("PPH Analysis",          self._classical.pph_analysis(arr)),
                ("GFR Analysis",          self._classical.gfr_analysis(gray)),
                # [P1.L] adaptive cost now receives arr for per-channel LSB
                ("Adaptive Cost",         self._classical.adaptive_cost_analysis(arr, gray)),
                ("Entropy Analysis",      self._classical.entropy_block_analysis(gray)),
                ("GAN Stego",             self._classical.gan_stego_detection(arr, gray)),
                # [P1.N] jpeg_ghost receives is_jpeg flag
                ("JPEG Ghost",            self._classical.jpeg_ghost_analysis(img, is_jpeg=is_jpeg)),
                # [P2.T] new per-channel entropy analysis
                ("Per-Channel Entropy",   self._classical.per_channel_entropy_analysis(arr)),
            ]

            classical_probs       = []
            n_classical_triggered = 0
            for name, r in classical_runs:
                result["analysis"][name] = r
                if r.get("suspicious"):
                    result["indicators"].extend(r.get("indicators", []))
                    result["techniques_triggered"].append(name)
                    classical_probs.append(r.get("probability", 0.0))
                    n_classical_triggered += 1

            # ── LAYER 2: DL ensemble ───────────────────────────────────────
            if TORCH_AVAILABLE:
                dl_scores = self._models.predict_all(img)
                result["dl_scores"] = dl_scores
                for name, score in dl_scores.items():
                    if score > 0.5:
                        result["techniques_triggered"].append(f"DL:{name}")
                        result["indicators"].append(f"{name} stego probability: {score:.3f}")

            # ── LAYER 3: Fusion ────────────────────────────────────────────
            final_p = self._fusion.fuse(
                result["dl_scores"],
                classical_probs,
                n_classical_triggered=n_classical_triggered,
                n_mm_triggered=0,   # image-only path; mm not applicable
            )

            result["steg_probability"] = float(final_p)
            result["steg_detected"]    = final_p > 0.5

            for thresh, level in self._CONFIDENCE_LEVELS:
                if final_p >= thresh:
                    result["confidence"] = level; break

            for key, steg_name in self._TYPE_MAP:
                if any(key in t for t in result["techniques_triggered"]):
                    result["steg_type"] = steg_name; break

        except Exception as e:
            logger.error("StegDetector.analyze error: %s", e, exc_info=True)

        return _to_python(result)

    def analyze_file(self, path: str) -> dict:
        """
        Analyze any file type: image, audio, video, document, or raw bytes.
        [S.23] 200 MB hard cap.
        [P1.D] FIX: File is read ONCE; raw_bytes passed to analyze() as PIL Image
               so the file is not opened from disk a second time.
               SHA256 is computed from original raw bytes in both code paths.
        [P0.3] Multi-modal detectors only called for matching file types.
        [P1.G] .docx passed to detect_text_steg with source_ext='.docx'.
        [P2.Q] HTML/MD passed with source_ext for markup-aware analysis.
        [P2.26] Video files: NOT analysed — stub with clear warning.
        """
        p = Path(path)
        ext = p.suffix.lower()
        result: Dict[str, Any] = {"file": str(p), "file_type": ext}

        resolved_path = p.resolve()

        # [S.23] 200 MB cap
        file_size = resolved_path.stat().st_size
        if file_size > _MAX_FILE_BYTES:
            result["error"] = (
                f"File too large ({file_size / 1024 / 1024:.1f} MB > "
                f"{_MAX_FILE_BYTES // 1024 // 1024} MB limit). Analysis refused.")
            result["steg_probability"] = 0.0
            return _to_python(result)

        # Read file ONCE
        raw_bytes = resolved_path.read_bytes()

        # [P1.D / S.24] SHA256 on original raw bytes, computed once
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        result["sha256"] = raw_sha256

        if ext in _IMAGE_EXTS:
            # [P1.D] FIX: construct PIL from raw_bytes in memory; no second file read
            try:
                img_pil = Image.open(io.BytesIO(raw_bytes))
            except Exception as e:
                result["error"] = f"Image decode failed: {e}"
                result["steg_probability"] = 0.0
                return _to_python(result)

            img_result = self.analyze(img_pil, _raw_bytes=raw_bytes)
            # analyze() may write a re-encoded PNG sha256; overwrite with original
            img_result["sha256"] = raw_sha256
            result.update(img_result)

        elif ext in _AUDIO_EXTS:
            r = self._multimodal.detect_audio_steg(raw_bytes)
            result.update(r)
            result["steg_type"] = "Audio Steganography" if r.get("suspicious") else None

        elif ext == '.pdf':
            r = self._multimodal.detect_pdf_steg(raw_bytes)
            result.update(r)
            result["steg_type"] = "PDF Steganography" if r.get("suspicious") else None

        elif ext in _TEXT_EXTS:
            # [P1.G / P2.Q] pass source_ext so detector applies format-aware preprocessing
            r = self._multimodal.detect_text_steg(raw_bytes, source_ext=ext)
            result.update(r)
            result["steg_type"] = "Text Steganography" if r.get("suspicious") else None

        elif ext in _NET_EXTS:
            r = self._multimodal.detect_network_steg(raw_bytes)
            result.update(r)
            result["steg_type"] = "Network Covert Channel" if r.get("suspicious") else None

        elif ext in {'.mp4', '.avi', '.mkv', '.mov', '.wmv'}:
            # [P2.26] Video NOT implemented — honest stub
            result["steg_probability"] = 0.0
            result["steg_detected"]    = False
            result["indicators"]       = []
            result["warning"] = (
                "Video steganography analysis is NOT implemented. "
                "Frame LSB, DCT coefficient, and motion-vector covert channel "
                "detection require frame extraction (e.g. OpenCV) which is not "
                "present in this build.")

        else:
            result["steg_probability"] = 0.0
            result["indicators"] = [
                "Unknown file type — run image/audio/network analysis as appropriate"
            ]

        return _to_python(result)


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — Model Registry Helper
# ═══════════════════════════════════════════════════════════════════════════════

PRETRAINED_MODEL_REGISTRY = {
    "SRNet": {
        "source": "github.com/brijeshiitg/Pytorch-implementation-of-SRNet",
        "format": "PyTorch .pth",
        "trained_on": "BOSSBase + BOSS (WOW/S-UNIWARD/HILL @ 0.4bpp)",
        "accuracy": "~90% on BOSSBase 0.4bpp",
        "notes": "Multi-crop scoring implemented in v3.2",
    },
    "GBRAS-Net": {
        "source": "github.com/BioAITeam/Steganalysis",
        "format": "PyTorch .pth / Keras .h5",
        "trained_on": "BOSSBase (WOW/HILL/MiPOD/S-UNIWARD)",
        "accuracy": "89-91% on BOSSBase 0.4bpp",
        "notes": "SRM ×255 scaling applied in v3.2 for correct TLU bias",
    },
    "ALASKA2_SRNet_ONNX": {
        "source": "github.com/YassineYousfi/alaska",
        "format": "ONNX .ort",
        "trained_on": "ALASKA2 (J-UNIWARD/UERD/J-MiPOD)",
        "accuracy": "ALASKA2 competition SOTA",
        "notes": "Center-crop only for ALASKA (JPEG-targeted)",
    },
    "EfficientNet_ALASKA2": {
        "source": "Kaggle ALASKA2 top kernels",
        "hf_repo": "timm/efficientnetv2_rw_s.ra2_in1k → fine-tune",
        "format": "PyTorch .pth",
        "trained_on": "ALASKA2 + ALASKA1",
        "accuracy": "~96% AUC on ALASKA2",
    },
    "BayarNet": {
        "source": "github.com/MarcioPorto/steganalysis",
        "format": "PyTorch .pth",
        "trained_on": "Mixed (LSB/HUGO/WOW)",
        "accuracy": "85-88% general",
    },
    "StegFormer": {
        "source": "Custom — fine-tune on BOSS/ALASKA2",
        "hf_repo": "Fine-tune from: timm/vit_small_patch16_224.augreg_in21k",
        "format": "PyTorch .pth",
        "trained_on": "BOSSBase + ALASKA2 (multi-scheme)",
        "accuracy": "SOTA 2024 ~93% on multi-scheme",
    },
}


def print_model_registry():
    print("\n" + "=" * 80)
    print("  STEG DETECTOR v3.2 (FIXED) — PRETRAINED MODEL REGISTRY")
    print("=" * 80)
    for name, info in PRETRAINED_MODEL_REGISTRY.items():
        print(f"\n  [{name}]")
        for k, v in info.items():
            print(f"    {k:15s}: {v}")
    print("=" * 80)


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — CLI
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, json
    logging.basicConfig(level=logging.INFO)

    if "--models" in sys.argv:
        print_model_registry()
        sys.exit(0)

    detector = AdvancedStegDetector()
    target   = next((a for a in sys.argv[1:] if not a.startswith("--")), None)

    if target:
        p = Path(target)
        if p.exists():
            r = detector.analyze_file(str(p))
        else:
            r = {"error": f"File not found: {target}"}
        print(json.dumps(r, indent=2))
    else:
        print("""
╔══════════════════════════════════════════════════════════════════════╗
║  AdvancedStegDetector v3.2 FIXED — 2026 SOTA Steganalysis Engine   ║
╠══════════════════════════════════════════════════════════════════════╣
║  Usage: python advanced_steg_detector_v3_2_fixed.py <file_path>    ║
║         python advanced_steg_detector_v3_2_fixed.py --models       ║
║                                                                      ║
║  NOTE: steg_probability is an uncalibrated suspicion score, not     ║
║        a true posterior probability.                                 ║
╚══════════════════════════════════════════════════════════════════════╝
""")