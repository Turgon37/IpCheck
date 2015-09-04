# IpCheck - Ip address Checker script

This script must be run as a routine, it check regularly your external (public) ip address and keep it up to date in a local file world readable

Currently, the script keep a file up to date with your current public IP(v4) address and can run a command (see --command) after each update

The bash script ipcheck.sh is in this repository only for history backup. DO NOT USE IT, please prefer using the python version instead.

## Usage

```bash
  ./ipcheck.py
```

Please use the --help statement on the script to learn how to use it


## Installation

Just put it into a folder and run it. You can configure a periodic call system, like cron, to execute it regularly

##### Requires:
  - python version
    * python >= 3.2