# Traffic stream and virtual sensor

> Response update: Monitor, simulated blocking/rate-limiting, uncertainty labeling and advisory behavioral evidence are documented in [RESPONSE_AND_BEHAVIOR.md](RESPONSE_AND_BEHAVIOR.md). Its repeated-reference simulation counts supersede earlier scenario counts below.


The main workspace now places an animated packet-activity wave above the existing statistics. The waveform, dots, detection feed, donut and flow table follow one shared replay position. Attack markers use actual model verdicts, not the reference labels or random events.

## Start a simulation

1. Open http://127.0.0.1:8000 and refresh the page.
2. Leave the address as **192.0.2.10**. Select Mixed traffic, DDoS sequence, Botnet sequence or Unseen attack.
3. Click **Connect sensor**. The actual active classifier analyzes the prepared sequence; playback begins when inference finishes.
4. Use **Pause/Play**, **Restart**, the timeline slider and **0.5×–4×** speed. Enable **Loop** to repeat the same sequence. Counters reset for each cycle.
5. Click a detection marker or a card in **Detection feed** to pause and inspect its evidence. The table's Inspect control does the same.

**Traffic stream** remains a dedicated navigation tab. The duplicate **Test & demo** tab has been removed; the independent labeled evaluation API/CLI remains available.

## Packet and threat logging

The **Packet & threat log** follows the same replay cursor as the wave. Each recorded frame produces its own PACKET entry with its original capture sequence, timestamp, byte length, protocol and endpoints when supported. Frames unsupported by the classifier and packets beyond its first-16-packet context are still logged. THREAT entries are accepted botnet/DDoS flow predictions; REVIEW entries are UNKNOWN flow outcomes. Verdicts are inserted at flow readiness, separately from packet arrival. These are replay events from precomputed inference, not a live network sensor.

Filter All events, Packets, Threats or Review. Threat and review rows open flow evidence. The screen renders 200 newest matching entries per page; Older/Newer and Follow latest provide access to every revealed event without an unbounded DOM. **Export log** saves all revealed matching events, not just the visible page. Seeking backwards removes future events; restarting or looping resets the log. Old saved investigations show a packet-log-unavailable message rather than fabricated packet entries.

Every scenario includes per-phase reference names, packet counts and SHA-256 digests of length-prefixed original frame bytes. A scenario-wide content digest excludes retimed timestamps so repeated runs remain comparable. Mixed uses normal → botnet → DDoS → unseen; the others use normal → selected attack → normal. Shared baseline/reference packets are intentional; the four complete sequences have distinct content hashes. Choosing a dropdown option and clicking Connect sensor loads that sequence.

## Model & validation

The screen reads measurements from the active checkpoint's audit. Primary cards show median model inference speedup, milliseconds saved per 64-flow batch, held-out accuracy and macro F1. A table shows paired CPU PyTorch and GPU TensorRT median and p95 times and computes their differences and ratios. The active audit records 12.955 ms versus 0.581 ms median: 12.374 ms saved, approximately 22.3× faster. This compares the same checkpoint on CPU and GPU; it does not measure savings over a legacy PNG pipeline or competitor. Transfers are included; parsing, flow waiting, HTTP and packet-log rendering are excluded. The latest capture's analysis duration is shown separately.

Supporting cards show rejection and benign escalation, class counts, class agreement, deployment gates and implementation strengths. No universal best-model claim is made. Missing paired audits display Not measured rather than estimated savings. The model and decision policy are unchanged by the logging/UI work.

`192.0.2.10` is a display-only virtual sensor address, not an IP assigned to your laptop, a remote machine or a public service. The simulator retimes real public reference frames inside a PCAP held in server memory. **It does not send attack packets, scan hosts, capture laptop traffic or contact the entered address.** Original packet endpoint addresses remain available as evidence; the virtual sensor address identifies the replay source.

Each scenario is analyzed afresh by the unchanged model. Retiming can change session grouping, so simulator counts need not equal the separate demo suite. The scenario names describe which reference traffic was included; they never force attack verdicts. UNKNOWN remains a review outcome, not a successful attack-type prediction. The existing experimental banner and production release gates remain enforced.

## Upload and focus

Uploading a PCAP/PCAPNG automatically prepares a capture replay. Original timestamp relationships are fitted to a **30-second playback timeline**, with selectable speed. The capture clock shows original UTC time. A short single-packet capture is valid; a flow can remain UNKNOWN when context is insufficient.

Enter an IPv4/IPv6 address that occurs in a supported flow and click **Focus host**. With packet logging available, the wave, log and packet statistics describe all recorded packets for that host, including packets outside model context; verdicts still refer to its represented flows. Legacy investigations use represented flow packets only. Clear focus with **×**. This is a filter over uploaded data; an arbitrary IP alone cannot provide network traffic.

Older saved investigations without full packet timelines still replay their represented flow context. A note identifies that reduced coverage.

## Read the visualization

- **Wave / teal dots:** Packet activity. Wave height is a stylized measure of local packet density; dense intervals are grouped into at most 512 points. Dots are not all automatically benign verdicts.
- **Amber/red rings:** Accepted botnet/DDoS predictions. Markers appear after their flow context is available.
- **Grey review rings:** UNKNOWN verdicts.
- **Detection feed:** The five latest revealed non-benign verdicts, with clickable endpoints and evidence. It follows backward seeking too.
- **Packets observed:** Individual logged packets reached by the replay cursor. Legacy captures use grouped timeline counts; host focus is labeled with its coverage.
- **Flow bursts / threats / donut / table:** Only predictions revealed at that point, never future verdicts.
- **Capture elapsed:** Progress through the capture's timestamp span. The separate small analysis-time label is the measured precomputed processing time; it is not an animated inference benchmark.
- **Export report:** Exports the complete analyzed capture, including predictions not yet revealed in playback. The filtered CSV exports the currently revealed matching flows.

This is a visualization of already-computed inference, not live packet-by-packet inference. Playback compression does not change the uploaded file's timestamps. Simulation intentionally retimes reference packets and marks that distinction. Pausing, seeking and looping do not retrain or rerun the model.

Playback pauses when a tab becomes hidden or when another main screen is opened. Reduced-motion users get an explicit Play control for uploaded captures. Clicking **Connect sensor** or **Restart** explicitly starts playback, including with reduced motion enabled; decorative attack pulses remain suppressed for that preference. Connection progress and failures appear immediately below the sensor controls, and a failed request enables retry. The canvas is display-scaled for high-DPI devices and bounds visible markers; equivalent detection buttons and live status text provide a keyboard-accessible inspection path.

## Verification

Replay core tests cover zero initial/final counts, no premature detections, deterministic backward seeking, IPv4/IPv6 focus, legacy history, zero-duration captures, and delayed partial-flow readiness. Backend tests cover 100,000-packet binning, timeline count/byte conservation, and virtual-address validation. GPU HTTP checks verify all four scenarios, authentication and forced UNKNOWN under failed release gates. An actual GPU response was also replayed through the JavaScript core and its final counts matched the API exactly.

Controller regression checks execute the three shipped JavaScript files against a minimal DOM and controlled animation clock. They exercise Connect through completion, explicit start with reduced motion, connection failures, pause, seeking, restart, loop and reset. All four actual GPU scenario responses also completed this controller playback with identical final packet, flow and verdict counts. These checks do not inspect browser rendering. The page and static assets now revalidate on refresh to pick up a redeployed version.

Packet-log update verification on the local GPU app:

| Scenario | Logged packets | Flow bursts | Frame-content SHA-256 prefix |
|---|---:|---:|---|
| Mixed | 1,019 | 89 | `df9c224d983d` |
| DDoS | 852 | 60 | `e1c421aaa06a` |
| Botnet | 741 | 31 | `22f00c5c6b18` |
| Unseen | 916 | 60 | `e21b01b45316` |

All four content hashes differ. Packet counts and byte totals match capture telemetry; model counts and every fingerprint match the previous app. Backend regression suite: 27 passed, one native-extension check skipped on Windows. Frontend suite with an actual GPU response: 16 passed. Additional checks cover exact packet logging beyond model context, unsupported frames, early packet arrival before a threat verdict, log filtering, 200-row paging with complete export, dropdown request selection and measured model cards. No longevity test or training was started.

The wave timing is deterministic from the response; no random traffic or fabricated attack alerts are generated. Model accuracy limitations remain unchanged. Visual appearance is pending the user's review because local browser automation was disabled, and the user chose to review it manually.

Run the checks:

```text
node --test tests/stream.test.cjs tests/stream-ui.test.cjs
python -m pytest -q
python -m scripts.deployment_smoke --gpu --model candidate_flow_resnet
```

The earlier 24-hour longevity replay remains stopped. Looping the browser visualization is a separate, optional display action.
