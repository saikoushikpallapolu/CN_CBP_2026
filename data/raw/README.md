# Raw Data Documentation

## Current Structure

```
data/raw/
    benign/
        Monday-WorkingHours_slice100MB.pcap
    botnet/
        Friday-WorkingHours_slice100MB.pcap
    ddos/
        Wednesday-workingHours_slice100MB.pcap
```

**IMPORTANT:** Currently only one independent PCAP source is available for each class. Cross-source evaluation cannot yet be performed.

## Future Structure

To support genuine cross-source generalizability testing, the raw data directory must be expanded to include completely independent PCAP files for each class:

```
data/raw/
    benign/
        source_A/
        source_B/
    botnet/
        source_A/
        source_B/
    ddos/
        source_A/
        source_B/
```

*Note: Do NOT create fake source directories containing copies of the existing files. A genuine source must be a distinct, separately captured network stream.*
