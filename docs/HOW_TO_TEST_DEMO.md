# How to test the demo yourself (PCAP → bytes → grayscale image)

## Why the real image looks pixelated

The project uses **64 × 64** images on purpose (4096 bytes → 4096 pixels).
That is the size the CNN will train on. It will look blocky if you open it large.

The demo now also creates a **zoomed preview (512 × 512)** so you can see the pattern.

---

## Step-by-step test

### 1. Open a terminal in the project folder

```powershell
cd "C:\Users\Sai Koushik\Desktop\CN_CBP_2026\CN_CBP_2026"
.\.venv\Scripts\Activate.ps1
```

### 2. Pick what to “upload” (use a file path)

You do **not** need a web upload. Pass a PCAP path as the argument.

**Easiest — use our sample files:**

| What you want to try | File to use |
|----------------------|-------------|
| Benign traffic | `data\raw\benign\Monday-WorkingHours_slice100MB.pcap` |
| DDoS / DoS day | `data\raw\ddos\Wednesday-workingHours_slice100MB.pcap` |
| Botnet day | `data\raw\botnet\Friday-WorkingHours_slice100MB.pcap` |

**Or your own PCAP:** copy any `.pcap` / `.pcapng` somewhere and use its full path.

### 3. Run the demo

**Benign sample:**

```powershell
python scripts/demo_pcap_to_image.py data/raw/benign/Monday-WorkingHours_slice100MB.pcap
```

**Your own file:**

```powershell
python scripts/demo_pcap_to_image.py "C:\full\path\to\your_file.pcap"
```

### 4. What to look at in the TERMINAL

You should see sections like:

1. **INPUT FILE** — the PCAP path you gave  
2. **BYTE LIST** — numbers like `[184, 172, 111, 54, ...]`  
   - each number is **0–255**  
   - these become pixel brightness (0=black, 255=white)  
3. **REAL MODEL IMAGE** — path to the tiny `64x64` PNG  
4. **ZOOMED PREVIEW** — path to the large image you should look at  

### 5. What to look at in the IMAGE VIEWER

The script opens the **zoomed** file automatically, e.g.:

- `data\processed\demo_preview_zoomed_512.png`

You should see a **gray textured square** (stripes / noise / blocks) — that is the traffic bytes drawn as an image.

Also saved (but tiny):

- `data\processed\demo_preview.png` ← real 64×64 used by the pipeline

---

## Optional: save without opening a window

```powershell
python scripts/demo_pcap_to_image.py data/raw/ddos/Wednesday-workingHours_slice100MB.pcap --no-open
```

Then open the `*_zoomed_512.png` file yourself from File Explorer.
