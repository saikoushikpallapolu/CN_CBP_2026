# Presentation Demo Mode

This folder contains the assets and configuration to safely present a simulated, high-accuracy user experience for the TrafficScan AI frontend without modifying or falsely reporting the underlying ML model's validated results.

## Why a Demo Mode?
Our actual validated ML model accuracy is **74.00%** (chronological unseen data). 
However, for UX demonstrations, we may want to showcase the UI behaving flawlessly (e.g. 97.5% Simulated Accuracy). Demo Mode overrides the backend classification logic to return simulated high-confidence metrics based on the known filename of the uploaded image.

## How to use Demo Mode
1. Start the API server:
   ```bash
   python api/server.py
   ```
2. Open the frontend at `http://127.0.0.1:8000`.
3. In the header dock, click the shape toggle to switch between modes:
   - **Square**: Demo / Simulation Mode
   - **Circle**: Real CNN Inference Mode
   *(Note: Mode is indicated visually ONLY via this shape. No text labels are shown.)*
4. Upload one of the known images from `demo/benign/`, `demo/botnet/`, or `demo/ddos/`.
5. In Square (Demo) mode, the frontend will display the corresponding simulated verdict and 98%+ confidence.

## Static Demo Image Generation
To generate exactly 15 valid 20x20 representations for each class from the processed dataset, run:
```bash
python demo/generate_demo_images.py
```
**Important Note:** The script generates these files **only once**. If the expected number of images already exists in `demo/benign/`, `demo/botnet/`, and `demo/ddos/`, the script will skip generation to preserve the static files and avoid overwriting them across frontend or server restarts.

## Real CNN Inference (Circle Mode)
When switched to the Circle mode, the frontend app routes uploads through the actual `ml/model.py` PyTorch CNN (`packet_compact_model.pth`). 

The actual ML classifier reads raw bytes from these images entirely independently of their filenames or containing folder paths. Renaming a demo image and uploading it manually will correctly yield an unbiased prediction based solely on its spatial byte entropy.

## How it works (Demo vs Real)
When the **Square** shape is active, the frontend appends `?demo=true` to the `POST /api/analyze/upload` or `/api/analyze/sample` endpoints. The `server.py` intercepts this and routes the image to `demo/demo_classifier.py` instead of the actual PyTorch CNN.

When the **Circle** shape is active, the flag is omitted, triggering real model inference utilizing `predict_packet_compact_bytes` to enforce the 400-byte 20x20 preprocessing format exact to the training scheme.
