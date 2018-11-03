# audit_log_parser

It is a library for parsing [linux's audit log](https://github.com/linux-audit/audit-documentation/wiki).

[![Gem Version](https://badge.fury.io/rb/audit_log_parser.svg)](http://badge.fury.io/rb/audit_log_parser)
[![Build Status](https://travis-ci.org/winebarrel/audit_log_parser.svg?branch=master)](https://travis-ci.org/winebarrel/audit_log_parser)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'audit_log_parser'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install audit_log_parser

## Usage

```ruby
#!/usr/bin/env ruby
require 'audit_log_parser'
require 'pp'

audit_log = <<EOS
type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=500 uid=500 gid=500 euid=500 suid=500 fsuid=500 egid=500 sgid=500 fsgid=500 tty=pts0 ses=1 comm="cat" exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"
EOS

pp AuditLogParser.parse_line(audit_log)
#=> {"header"=>{"type"=>"SYSCALL", "msg"=>"audit(1364481363.243:24287)"},
#    "body"=>
#     {"arch"=>"c000003e",
#      "syscall"=>"2",
#      "success"=>"no",
#      "exit"=>"-13",
#      "a0"=>"7fffd19c5592",
#      "a1"=>"0",
#      "a2"=>"7fffd19c4b50",
#      "a3"=>"a",
#      "items"=>"1",
#      "ppid"=>"2686",
#      "pid"=>"3538",
#      "auid"=>"500",
#      "uid"=>"500",
#      "gid"=>"500",
#      "euid"=>"500",
#      "suid"=>"500",
#      "fsuid"=>"500",
#      "egid"=>"500",
#      "sgid"=>"500",
#      "fsgid"=>"500",
#      "tty"=>"pts0",
#      "ses"=>"1",
#      "comm"=>"\"cat\"",
#      "exe"=>"\"/bin/cat\"",
#      "subj"=>"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
#      "key"=>"\"sshd_config\""}}
```
