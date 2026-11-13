# frozen_string_literal: true

# A collector that stands in for ours: answers every endpoint the package
# calls and records what reached it. Used by the tests, and on its own by the
# Rails and Sinatra checks:
#
#     ruby test/support/fake_collector.rb 4000 rules.json
#
# GET /_seen returns what it recorded (JSON); POST /_rules replaces the rules.

require "json"
require "socket"

class FakeCollector
  TRACKER = "// a tracker\n#{'x' * 600}"
  DEFAULT_RULES = { "v" => 1, "enabled" => true, "mode" => "monitor", "sync" => 30 }.freeze

  attr_reader :port, :seen
  attr_accessor :rules, :config, :answers

  def initialize(port = 0, rules = DEFAULT_RULES)
    @server = TCPServer.new("0.0.0.0", port)
    @port = @server.addr[1]
    @rules = rules
    @config = { "v" => 1, "modules" => {}, "sync" => 30 }
    @answers = {}
    @seen = []
    @lock = Mutex.new
  end

  def endpoint
    "http://127.0.0.1:#{@port}"
  end

  def start
    @thread = Thread.new do
      loop do
        client = @server.accept
        Thread.new(client) { |c| serve(c) }
      rescue IOError, SystemCallError
        break
      end
    end
    self
  end

  def stop
    @server.close
    @thread&.kill
  end

  def requests(path_prefix = nil)
    @lock.synchronize { @seen.dup }.select { |r| path_prefix.nil? || r["path"].start_with?(path_prefix) }
  end

  def clear
    @lock.synchronize { @seen.clear }
  end

  def serve(client)
    line = client.gets.to_s
    method, target, = line.split(" ")
    headers = {}
    while (h = client.gets) && h != "\r\n"
      name, value = h.split(":", 2)
      headers[name.downcase] = value.to_s.strip
    end
    length = headers["content-length"].to_i
    body = length.positive? ? client.read(length) : ""
    status, type, out, extra = answer(method.to_s, target.to_s, headers, body)
    client.write("HTTP/1.1 #{status} X\r\nContent-Type: #{type}\r\nContent-Length: #{out.bytesize}\r\n#{extra}Connection: close\r\n\r\n#{out}")
  rescue StandardError
    nil
  ensure
    client.close rescue nil # rubocop:disable Style/RescueModifier
  end

  def answer(method, target, headers, body)
    path = target.split("?", 2)[0]
    return [200, "application/json", JSON.generate(@lock.synchronize { @seen.dup }), ""] if path == "/_seen"

    if path == "/_rules" && method == "POST"
      @rules = JSON.parse(body)
      return [200, "application/json", "{}", ""]
    end
    parsed = begin
      body.empty? ? nil : JSON.parse(body)
    rescue JSON::ParserError
      body
    end
    @lock.synchronize { @seen << { "method" => method, "path" => path, "target" => target, "headers" => headers, "body" => parsed } }
    custom = @answers[path]
    return custom.call(method, headers, parsed) if custom

    case path
    when "/events/firewall/rules"
      etag = "\"#{JSON.generate(@rules).hash.abs}\""
      return [304, "application/json", "", "ETag: #{etag}\r\n"] if headers["if-none-match"] == etag

      [200, "application/json", JSON.generate(@rules), "ETag: #{etag}\r\n"]
    when "/events/platform/config"
      [200, "application/json", JSON.generate(@config), ""]
    when "/events/inventory", "/events/posture"
      [200, "application/json", '{"v":1,"enabled":true,"every":86400}', ""]
    when "/events/resources"
      [200, "application/json", '{"v":1,"enabled":true,"every":300}', ""]
    when "/collectanalytics/shield/verify"
      [200, "application/json", '{"success":true,"reasons":[]}', ""]
    when "/events/lead"
      [200, "application/json", '{"status":"created","lead_id":"l1"}', ""]
    when %r{\A/v[0-9.]+/[a-z]+\.js\z}
      [200, "application/javascript", TRACKER, ""]
    else
      [202, "application/json", '{"status":"accepted"}', ""]
    end
  end
end

if $PROGRAM_NAME == __FILE__
  rules = ARGV[1] ? JSON.parse(File.read(ARGV[1])) : FakeCollector::DEFAULT_RULES
  collector = FakeCollector.new((ARGV[0] || 4000).to_i, rules).start
  warn "fake collector on #{collector.port}"
  trap("TERM") { exit }
  trap("INT") { exit }
  sleep
end
