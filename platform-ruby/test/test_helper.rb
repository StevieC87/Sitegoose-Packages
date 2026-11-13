# frozen_string_literal: true

#     cd sdk/platform-ruby && ruby -Ilib -Itest -e 'Dir["test/*_test.rb"].each { |f| require_relative f }'
# or  bundle exec rake test

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "minitest/autorun"
require "json"
require "stringio"
require "sitegoose"
require_relative "support/fake_collector"

PROTOCOLS = File.expand_path("../../protocols", __dir__)
HTML = "text/html,application/xhtml+xml,*/*;q=0.8"

def shared(name)
  JSON.parse(File.read(File.join(PROTOCOLS, name)))
end

# A core that sends nothing: tests flush by hand, and see what would have gone.
class FakeCore
  attr_reader :sent, :site_id, :secret, :endpoint, :server_name
  attr_accessor :answers, :switches, :flags_given, :maintenance_given

  def initialize(secret: "s", answers: [], valid: false)
    @secret = secret
    @site_id = "a" * 24
    @endpoint = "http://collector.invalid"
    @server_name = "test"
    @answers = answers
    @sent = []
    @valid = valid
    @switches = {}
    @flags_given = {}
    @maintenance_given = { "on" => false }
  end

  def valid?
    @valid
  end

  def on?(name)
    @switches[name] != false
  end

  def flags
    @flags_given
  end

  def maintenance
    @maintenance_given
  end

  def security_headers
    []
  end

  def log(*); end

  def request(mod, path, method: "POST", body: nil, auth: :body, headers: nil)
    @sent << { mod: mod, path: path, method: method, body: body, auth: auth, headers: headers }
    status = @answers.empty? ? 202 : @answers.shift
    return nil if status.nil?

    status.is_a?(SiteGoose::Response) ? status : SiteGoose::Response.new(status, {}, "{}")
  end
end

# Every module off but the ones named, with no site: nothing is sent.
def quiet_platform(**on)
  options = SiteGoose::MODULES.to_h { |name| [name.to_sym, false] }.merge(on)
  made = nil
  silence { made = SiteGoose::Platform.new(site_id: "", secret: "s", endpoint: "", **options) }
  made
end

def silence
  saved = $stderr
  $stderr = StringIO.new
  yield
ensure
  $stderr = saved
end

def rack_env(method: "GET", path: "/pricing", query: "", accept: HTML, remote: "203.0.113.5", **headers)
  env = {
    "REQUEST_METHOD" => method, "PATH_INFO" => path, "QUERY_STRING" => query, "SCRIPT_NAME" => "",
    "REMOTE_ADDR" => remote, "rack.input" => StringIO.new(""), "HTTP_ACCEPT" => accept
  }
  headers.each { |k, v| env["HTTP_#{k.to_s.upcase}"] = v }
  env
end

# A firewall with these rules already in place.
def wall(rules, core: FakeCore.new, **options)
  made = SiteGoose::Firewall.new(core, **options)
  made.rules = made.compile({ "v" => 1, "enabled" => true }.merge(rules))
  made
end

SITE = ->(_env) { [200, { "content-type" => "text/plain" }, ["the site"]] }

def body_of(response)
  out = +""
  response[2].each { |part| out << part }
  out
end
