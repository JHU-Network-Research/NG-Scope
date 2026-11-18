# IMSIGUARD GUI

This is a desktop application for running IMSI-Guard, an authentication-based IMSI-Catcher detector. 
It is a wrapper around NG-Scope that applies post-processing scripts to look for IMSI-Catchers.

## Run

To run the application, just run:
```bash
./imsiguard-gui/imsiguard-gui
``` 
from a terminal. Configure any desired settings or use the defaults, tell it what frequencies to sweep, and IMSI-Guard will begin its earch for IMSI-Catchers.

## Requirements

IMSI-Guard does require that NG-Scope be built and discoverable on the system.
