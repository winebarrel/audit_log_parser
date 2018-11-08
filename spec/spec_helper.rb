require 'bundler/setup'
require 'audit_log_parser'

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

module SpecHelper
  def flatten(hash)
    header = hash.fetch('header')
    body = hash.fetch('body')

    new_hash = (
      header.map {|k, v| ["header_#{k}", v] } +
      body.map {|k, v| ["body_#{k}", v] }
    ).to_h

    if new_hash.has_key?('body_msg')
      body_msg = new_hash.delete('body_msg')

      body_msg.each do |k, v|
        new_hash["body_msg_#{k}"] = v
      end
    end

    new_hash
  end
end
include SpecHelper
