# audit_log_parser

It is a library for parsing [linux's audit log](https://github.com/linux-audit/audit-documentation/wiki).

[![Gem Version](https://badge.fury.io/rb/audit_log_parser.svg)](http://badge.fury.io/rb/audit_log_parser)
[![Build Status](https://travis-ci.org/winebarrel/audit_log_parser.svg?branch=master)](https://travis-ci.org/winebarrel/audit_log_parser)
[![](https://img.shields.io/badge/rubydoc-reference-blue.svg)](https://www.rubydoc.info/gems/audit_log_parser)

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

audit_log1 = <<EOS
type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=500 uid=500 gid=500 euid=500 suid=500 fsuid=500 egid=500 sgid=500 fsgid=500 tty=pts0 ses=1 comm="cat" exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"
EOS

pp AuditLogParser.parse_line(audit_log1)
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

audit_log2 = <<EOS
type=USER_AUTH msg=audit(1364475353.159:24270): user pid=3280 uid=500 auid=500 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:authentication acct="root" exe="/bin/su" hostname=? addr=? terminal=pts/0 res=failed'
EOS

pp AuditLogParser.parse_line(audit_log2)
#=> {"header"=>{"type"=>"USER_AUTH", "msg"=>"audit(1364475353.159:24270)"},
#    "body"=>
#     {"user pid"=>"3280",
#      "uid"=>"500",
#      "auid"=>"500",
#      "ses"=>"1",
#      "subj"=>"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
#      "msg"=>
#       {"op"=>"PAM:authentication",
#        "acct"=>"\"root\"",
#        "exe"=>"\"/bin/su\"",
#        "hostname"=>"?",
#        "addr"=>"?",
#        "terminal"=>"pts/0",
#        "res"=>"failed"}}}

audit_log3 = <<EOS
type=PATH msg=audit(1364481363.243:24287): item=0 name="/etc/ssh/sshd_config" inode=409248 dev=fd:00 mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0
EOS

pp AuditLogParser.parse_line(audit_log3, flatten: true)
#=> {"header_type"=>"PATH",
#    "header_msg"=>"audit(1364481363.243:24287)",
#    "body_item"=>"0",
#    "body_name"=>"\"/etc/ssh/sshd_config\"",
#    "body_inode"=>"409248",
#    "body_dev"=>"fd:00",
#    "body_mode"=>"0100600",
#    "body_ouid"=>"0",
#    "body_ogid"=>"0",
#    "body_rdev"=>"00:00",
#    "body_obj"=>"system_u:object_r:etc_t:s0"}
```

## Related Links

* [7.6. Understanding Audit Log Files - Red Hat Customer Portal](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files)
* [SPEC Writing Good Events · linux-audit/audit-documentation Wiki](https://github.com/linux-audit/audit-documentation/wiki/SPEC-Writing-Good-Events)
