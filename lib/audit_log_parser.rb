require 'strscan'
require 'audit_log_parser/version'

class AuditLogParser
  class Error < StandardError; end

  def self.parse(src)
    src.each_line.map do |line|
      parse_line(line)
    end
  end

  def self.parse_line(line)
    line = line.strip

    if line !~ /type=\w+ msg=audit\([\d.:]+\): /
      raise Error, "Invalid audit log header: #{line}"
    end

    header, body = line.split(/: /, 2)
    header.chomp!(': ')
    header = parse_header(header)
    body = parse_body(body)

    {
      'header' => header,
      'body' => body,
    }
  end

  def self.parse_header(header)
    result = {}

    header.split(' ').each do |kv|
      key, value = kv.split('=', 2)
      result[key] = value
    end

    result
  end
  private_class_method :parse_header

  def self.parse_body(body)
    unless body.include?('=')
      raise Error, "Invalid audit log body: #{body}"
    end

    result = {}
    ss = StringScanner.new(body)

    while key = ss.scan_until(/=/)
      if key.include?(', ')
        msg, key = key.split(', ', 2)
        result['_message'] = msg.strip
      end

      key.chomp!('=').strip!
      value = ss.getch

      case value
      when nil
        break
      when ' '
        next
      when '"'
        value << ss.scan_until(/"/)
      when "'"
        nest = ss.scan_until(/'/)
        nest.chomp!("'")
        value = parse_body(nest)
      else
        value << ss.scan_until(/( |\z)/)
        value.chomp!(' ')
      end

      result[key] = value
    end

    unless ss.rest.empty?
      raise "must not happen: #{body}"
    end

    result
  end
  private_class_method :parse_body
end
