## IMSI-Guard

IMSI-Guard is an IMSI-Catcher detection tool built on top of NG-Scope. 

### NG-Scope Changes

We added several features to NG-Scope to support IMSI-Guard:
- RNTI Filtering
- PDSCH decoding
- 4x2 MIMO Support
- PCAP output

We also add a gui to support IMSI-Guard, which is located in `imsiguard-gui` and can be run with 
```bash
./imsiguard-gui/imsiguard-gui
```

The rest of this document discusses the changes implemented in support of IMSI-Guard

### RNTI Filtering

In order to reduce the rates of spurious DCI decoding, we implement an RNTI filter that tracks the active valid RNTIs and ignores DCIs that do not have one of those RNTIs. 
Any non C-RNTI is automatically added to the valid list. Otherwise, RNTIs are added in two ways. First, if an RAR is successfully decoded, its C-RNTI is admitted. Additionally, if the RNTI doesn't have a corresponding RAR, we attempt to decode its corresponding PDSCH message and admit it to the RACH filter if the PDSCH message successfully decodes.

### PDSCH Decoding

We added active PDSCH decoding to NG-Scope to support IMSI-Guard's need of Authentication-Inferring Messagess, such as the SecurityModeCommand and DRBs. NG-Scope will attempt to decode the corresponding PDSCH message for every DCI it decodes, and uses this to infer real DCIs if the RNTI has yet to be seen.
NG-Scope cannot and will not attempt to decode any encrypted payloads in any PDSCH messages. 

### 4x2 MIMO

To improve PDSCH decoding performance, we add support for 4x2 MIMO decoding. Previously, srsRAN only supported the decoding of up to 2x2, but many LTE commercial cells use 4 transmit ports and supporting 4x2 MIMO with transmission modes 2, 3, and 4 increase NG-Scope's ability to reliably decode PDSCH messages. 

### PCAP output

When NG-Scope decodes any PDSCH message, rather than processing it live NG-Scope will output it to a pcap file to be processed separately.
