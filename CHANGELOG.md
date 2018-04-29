# Changelog

Items starting with `DEPRECATE` are important deprecation notices.

## 4.0.0 (2018-04-29)

### core

- Remove `-u`, `--url` command line option in favor to -u4 and --url-v4.
+ Refactor some functions to permit units tests

### advanced

- Removed support for 'url' config key in config.conf in favor to 'url_v4'
- Renamed error event type T_ERROR_FILE to T_ERROR_NOIP_FILE
- Renamed error event type T_ERROR_NOIP to T_ERROR_NOIP_URLS
- Renamed error event type T_ERROR_PERMS to T_ERROR_FILE
- Remove default value for digcheck nameserver, it allow to use the default nameserver configured in resolv.conf of the running host

### Deprecation


## 3.0.0 (2018-02-11)

### core

+ Rewrite the command line parser to use the argparse module.
+ Re-indent all the main classes
+ Add IPv6 configuration items (note that IPv6 is not fully enabled for now)

### advanced

+ Remove the project config parser, and move all its code into the loader

### Deprecation

- `DEPRECATE` `-u`, `--url` command line options and 'url' config key in config.conf in favor to -u4 and --url-v4.

## 2.2.0 (2015-09-20)

### core

+ Update logging string with new logging defintion

### advanced

+ Add message in mail extension in case when extension error occur

## 2.1.0 (2015-09-20)

### core

+ Improve logging message for all program

### advanced

+ Move Base class for extension into the init file of extension package
+ Add info_mail parameter into mail extension

## 2.0.1 (2015-05-25)

### advanced

+ Fix duplicate message when UPDATE event

## 2.0.0 (2015-04-25)

### core

+ Add ipcheckadvanced feature

### advanced

+ Add mail sender extension
+ Add command extension
+ Add dig checker extension

## 1.0.0 (2015-04-19)

First release of core python script
