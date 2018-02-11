# Changelog

Items starting with `DEPRECATE` are important deprecation notices.

## 3.0.0 (2018-02-11)

### core

+ Rewrite the command line parser to use the argparse module.
+ Re-indent all the main classes
+ Add IPv6 configuration items (note that IPv6 is not fully enabled for now)

### advanced

+ Remove the project config parser, and move all its code into the loader

### Deprecation

- Deprecate `-u`, `--url` command line option and 'url' config key in config.conf in favor to -u4 and --url-v4.

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