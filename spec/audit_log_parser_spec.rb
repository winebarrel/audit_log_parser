RSpec.describe AuditLogParser do
  let(:audit_log) do
    {
      %q{type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=500 uid=500 gid=500 euid=500 suid=500 fsuid=500 egid=500 sgid=500 fsgid=500 tty=pts0 ses=1 comm="cat" exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"} =>
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
          "op=PAM:authentication acct=\"root\" exe=\"/bin/su\" hostname=? addr=? terminal=pts/0 res=failed"}},
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
