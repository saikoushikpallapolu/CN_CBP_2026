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
3. In the header dock, check the **DEMO MODE** toggle switch.
4. Upload one of the known images from `demo/images/<class>/` (e.g. `benign_0001.png`).
5. The frontend will display the corresponding simulated verdict, 98%+ confidence, and explicitly label the result as **"DEMO / SIMULATION"**.

## Assets
- `demo/images/benign/`: 10 pre-processed 20x20 grayscale images of Benign traffic.
- `demo/images/botnet/`: 10 pre-processed 20x20 grayscale images of Botnet traffic.
- `demo/images/ddos/`: 10 pre-processed 20x20 grayscale images of DDoS traffic.

*(Note: These are exact copies from the generated `data/processed_packet_compact` dataset.)*

## How it works
When the **DEMO MODE** checkbox is active, the frontend appends `?demo=true` to the `POST /api/analyze/upload` or `/api/analyze/sample` endpoints. The `server.py` intercepts this and routes the image to `demo/demo_classifier.py` instead of the actual PyTorch CNN.

The demo classifier parses the filename and returns a hardcoded 98%+ probability for the matched class.

## Disabling Demo Mode
Simply uncheck the **DEMO MODE** toggle in the UI. 
The system will instantly revert to routing uploads through the actual `ml/model.py` PyTorch CNN (`packet_compact_model.pth`), returning the real confidence and classifying based on actual pixel arrays.
