# scripts/

## Demo: PCAP → bytes → grayscale image

Full instructions: **[docs/HOW_TO_TEST_DEMO.md](../docs/HOW_TO_TEST_DEMO.md)**

```powershell
.\.venv\Scripts\Activate.ps1
python scripts/demo_pcap_to_image.py data/raw/benign/Monday-WorkingHours_slice100MB.pcap
```

- Terminal shows the **byte list**
- Opens a **zoomed 512×512** preview (easy to see)
- Also saves the real **64×64** model image
