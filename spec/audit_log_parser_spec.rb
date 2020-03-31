RSpec.describe AuditLogParser do
  let(:audit_log) do
    {
      %q{type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=500 uid=500 gid=500 euid=500 suid=500 fsuid=500 egid=500 sgid=500 fsgid=500  tty=pts0 ses=1 comm="cat" exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"} =>
      {"header"=>{"type"=>"SYSCALL", "msg"=>"audit(1364481363.243:24287)"},
      "body"=>
        {"arch"=>"c000003e",
        "syscall"=>"2",
        "success"=>"no",
        "exit"=>"-13",
        "a0"=>"7fffd19c5592",
        "a1"=>"0",
        "a2"=>"7fffd19c4b50",
        "a3"=>"a",
        "items"=>"1",
        "ppid"=>"2686",
        "pid"=>"3538",
        "auid"=>"500",
        "uid"=>"500",
        "gid"=>"500",
        "euid"=>"500",
        "suid"=>"500",
        "fsuid"=>"500",
        "egid"=>"500",
        "sgid"=>"500",
        "fsgid"=>"500",
        "tty"=>"pts0",
        "ses"=>"1",
        "comm"=>"\"cat\"",
        "exe"=>"\"/bin/cat\"",
        "subj"=>"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        "key"=>"\"sshd_config\""}},
      # ---
      %q{type=CWD msg=audit(1364481363.243:24287):  cwd="/home/shadowman"} =>
      {"header"=>{"type"=>"CWD", "msg"=>"audit(1364481363.243:24287)"},
      "body"=>{"cwd"=>"\"/home/shadowman\""}},
      # ---
      %q{type=PATH msg=audit(1364481363.243:24287): item=0 name="/etc/ssh/sshd_config" inode=409248 dev=fd:00 mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0} =>
      {"header"=>{"type"=>"PATH", "msg"=>"audit(1364481363.243:24287)"},
      "body"=>
        {"item"=>"0",
        "name"=>"\"/etc/ssh/sshd_config\"",
        "inode"=>"409248",
        "dev"=>"fd:00",
        "mode"=>"0100600",
        "ouid"=>"0",
        "ogid"=>"0",
        "rdev"=>"00:00",
        "obj"=>"system_u:object_r:etc_t:s0"}},
      # ---
      %q{type=DAEMON_START msg=audit(1363713609.192:5426): auditd start, ver=2.2 format=raw kernel=2.6.32-358.2.1.el6.x86_64 auid=500 pid=4979 subj=unconfined_u:system_r:auditd_t:s0 res=success} =>
      {"header"=>{"type"=>"DAEMON_START", "msg"=>"audit(1363713609.192:5426)"},
      "body"=>
        {"_message"=>"auditd start",
        "ver"=>"2.2",
        "format"=>"raw",
        "kernel"=>"2.6.32-358.2.1.el6.x86_64",
        "auid"=>"500",
        "pid"=>"4979",
        "subj"=>"unconfined_u:system_r:auditd_t:s0",
        "res"=>"success"}},
      # ---
      %q{type=USER_AUTH msg=audit(1364475353.159:24270): user pid=3280 uid=500 auid=500 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:authentication acct="root" exe="/bin/su" hostname=? addr=? terminal=pts/0 res=failed'} =>
      {"header"=>{"type"=>"USER_AUTH", "msg"=>"audit(1364475353.159:24270)"},
      "body"=>
        {"user pid"=>"3280",
        "uid"=>"500",
        "auid"=>"500",
        "ses"=>"1",
        "subj"=>"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        "msg"=>
          {"acct"=>"\"root\"",
           "addr"=>"?",
           "exe"=>"\"/bin/su\"",
           "hostname"=>"?",
           "op"=>"PAM:authentication",
           "res"=>"failed",
           "terminal"=>"pts/0"}}},
      # ---
      %q{type=EOE msg=audit(1364475353.159:24270):} =>
      {"header"=>{"type"=>"EOE", "msg"=>"audit(1364475353.159:24270)"},
      "body"=>{}},
    }
  end

  context 'when succeed in parsing' do
    specify '#parse_line can be parsed correctly' do
      audit_log.each do |line, expected|
        expect(AuditLogParser.parse_line(line)).to eq expected
      end
    end

    specify '#parse can be parsed correctly' do
      lines = audit_log.keys.join("\n")
      expect(AuditLogParser.parse(lines)).to eq audit_log.values
    end

    specify '#parse unhex does not affect unhexable' do
      lines = audit_log.keys.join("\n")
      expect(AuditLogParser.parse(lines, unhex: true)).to eq audit_log.values
    end


    context 'when flatten' do
      specify '#parse can be parsed flatly' do
        lines = audit_log.keys.join("\n")
        expect(AuditLogParser.parse(lines, flatten: true)).to eq audit_log.values.map {|i| flatten(i) }
      end
    end
  end

  context 'when unhex log' do
    let(:unhex_audit_log) do
      {
        %q{type=PROCTITLE msg=audit(1585655101.154:27786): proctitle=2F62696E2F7368002D6300636F6D6D616E64202D762064656269616E2D736131203E202F6465762F6E756C6C2026262064656269616E2D73613120312031} => 
        {"header"=>{"type"=>"PROCTITLE", "msg"=>"audit(1585655101.154:27786)"},
        "body"=>
          {
            "proctitle" => "/bin/sh\u0000-c\u0000command -v debian-sa1 > /dev/null && debian-sa1 1 1", 
          }
        }
      }
    end

    let(:unhex_specific_audit_log) do
      {
        %q{type=PROCTITLE msg=audit(1585655101.154:27786): proctitle=2F62696E2F7368002D6300636F6D6D616E64202D762064656269616E2D736131203E202F6465762F6E756C6C2026262064656269616E2D73613120312031 proctitle2=2F62696E2F7368002D6300636F6D6D616E64202D762064656269616E2D736131203E202F6465762F6E756C6C2026262064656269616E2D73613120312031 } => 
        {"header"=>{"type"=>"PROCTITLE", "msg"=>"audit(1585655101.154:27786)"},
        "body"=>
          {
            "proctitle" => "2F62696E2F7368002D6300636F6D6D616E64202D762064656269616E2D736131203E202F6465762F6E756C6C2026262064656269616E2D73613120312031", 
            "proctitle2" => "/bin/sh\u0000-c\u0000command -v debian-sa1 > /dev/null && debian-sa1 1 1", 
          }
        }
      }
    end

    let(:unhex_length_audit_log) do
      {
        %q{type=PROCTITLE msg=audit(1585655101.154:27786): proctitle=2F62696E2F7368002D6300636F6D6D616E64202D762064656269616E2D736131203E202F6465762F6E756C6C2026262064656269616E2D73613120312031 } => 
        {"header"=>{"type"=>"PROCTITLE", "msg"=>"audit(1585655101.154:27786)"},
        "body"=>
          {
            "proctitle" => "2F62696E2F7368002D6300636F6D6D616E64202D762064656269616E2D736131203E202F6465762F6E756C6C2026262064656269616E2D73613120312031", 
          }
        }
      }
    end

    specify '#parse correctly unhex proctitle' do
      lines = unhex_audit_log.keys.join("\n")
      expect(AuditLogParser.parse(lines, unhex: true)).to eq unhex_audit_log.values
    end

    specify '#parse correctly unhex specific keys' do
      lines = unhex_specific_audit_log.keys.join("\n")
      expect(AuditLogParser.parse(lines, unhex: true, unhex_keys: ['proctitle2'])).to eq unhex_specific_audit_log.values
    end

    specify '#parse does not unhex short keys' do
      lines = unhex_length_audit_log.keys.join("\n")
      expect(AuditLogParser.parse(lines, unhex: true, unhex_keys: ['proctitle'], unhex_min_length: 10000)).to eq unhex_length_audit_log.values
    end
  end

  context 'when invalid log' do
    let(:invalid_log) do
      {
        audit_log.keys.first.delete('type') => /Invalid audit log header/,
        audit_log.keys.first.gsub(/\):.*\z/, '): xxx') => /Invalid audit log body/,
      }
    end

    specify '#parse_line throws an exception' do
      invalid_log.each do |line, expected|
        expect {
          AuditLogParser.parse_line(line)
        }.to raise_error expected
      end
    end

    specify '#parse_line throws an exception' do
      invalid_log.each do |line, expected|
        expect {
          AuditLogParser.parse(line)
        }.to raise_error expected
      end
    end
  end
end
