# IpCheck - Ip address Checker script

[![Build Status](https://travis-ci.org/Turgon37/IpCheck.svg?branch=master)](https://travis-ci.org/Turgon37/IpCheck)
[![codecov](https://codecov.io/gh/Turgon37/IpCheck/branch/master/graph/badge.svg)](https://codecov.io/gh/Turgon37/IpCheck)

This script must be run regularly (with tools like crontab), it check regularly your external (public) ip address and keep it up to date in a local file world readable. In addition to this, it perform some trigger action on IP update, like command execution and mail notification (see below advanced configuration)

---

**This tools is divided into two separate package.**

 * The base python script ```ipcheck.py``` run like a standalone program it can maintains your public ip address into a file and run a specific command after each update. To configure it, use the command line options like described below in 'Configuration' section

 * The ipcheckadvanced package is loaded automatically, if present in the same directory asthe standalone script, and add advanced feature to base program

**:warning: The bash script ipcheck.sh is in this repository only for history backup. DO NOT USE IT, please prefer using the python version instead.**

## Usage

```bash
  ./ipcheck.py
```

Please use the --help statement on the script to learn how to use all available option.

Advanced option will be shown only if there are available.

### Configuration

This script require at least one reacheable url to work properly. It will attempt to retrieve your system's external public IP address from the http content located at this URL. The option -u <url/> specify the program to use the given url. You can put more than one '-u' option to allow a list of url to be tested, this can prevent failure when a hostname become unavailable because the program will try the next hostname configured

:information_source: Note that the url must be of the form ```(http://)?hostname(:port)?/(path)?```

You can use the -v/--verbose option to cause the script prints out more debug informations

### Advanced Configuration

If the ipcheckadvanced package is installed in the same directory as the main script, advanced features will be available. These are called 'extensions'.
They consists in python class that are loaded during execution and according to declarations in a configuration file. Indeed, the advanced features require a configuration file for which the path can be configured by option '--config=<path>'

In this configuration file you can first list your url (see above), this prevent you to put theses into command line and you have to declare what extensions you want to use.

Each extensions is declared as a section in configuration. The section name must begin with 'extension.' and be put enclosed by bracket. The value after the point in the section name must define a python file in the subdirectory of the extensions that will be loaded into the program. This file must extends the ExtensionBase class defined in extensions init file. If you want to write your own extensions you can copy-paste 'skeleton.py' file and use it as template for your own class.

For event code and error type see this file [CONSTANTS](ipcheckadvanced/constant.py)

 * [Mail](doc/mail.md) - Receive program's notifications by mail
 * [Command](doc/command.md) - Execute specific command on event
 * [Digchecker](doc/digchecker.md) - Check a DYN Host by perform a DNS query

## Installation

Just put it into a folder and run it. You can configure a periodic call system, like cron, to execute it regularly.
If you want to use advanced features check that you have fill the configuration file. You can use the example config.conf given in repository.

##### Requires:
  - python version
    * python >= 3.4

### Example with a DYN Host update

  As example if you want to update a Dynamic DNS host after each IP address change you have to do the following instructions :

  Run the configuration script ```./configure``` and fill prompt with correct
  values

  OR

  * Download DynUpdate project at (https://github.com/Turgon37/DynUpdate) and put into **ipcheckadvanced/resources** directory
  * Put theses lines into configuration files
  ```
  [core]
  url = api.ipify.org/, bot.whatismyipaddress.com/

  [extension.digchecker]
  server = 8.8.8.8
  hostname = dynhost.yourdomainname.tld

  [extension.command]
  exec = dynupdate.py
  args = -a {ip} -s <dyn server address> -u <dynhost username> -p <dynhost password> -h <dynhost like dynhost.yourdomainname.tld>
  event = E_START, E_UPDATE
  ```
  * Add a line into your crontab like ```*/5 * * * * ./ipcheck.py --no-output --config=config.conf```
