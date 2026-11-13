# frozen_string_literal: true

# The core: the switches request and its check-in (X-Platform-App), sending
# to a real (fake) collector, and background threads after a fork.

require_relative "test_helper"

class CheckInTest < Minitest::Test
  def core(**options)
    SiteGoose::Core.new("a" * 24, "s", "http://127.0.0.1:9", **options)
  end

  def test_the_switches_request_says_which_service_asks_and_that_it_runs
    made = core(server_name: "api wörker")
    sent = nil
    made.define_singleton_method(:request) { |*_, **options| sent = options; nil }
    made.sync_switches
    header = sent[:headers]["X-Platform-App"]
    fields = URI.decode_www_form(header).to_h
    assert_equal ["api wörker", "process", Process.pid.to_s], fields.values_at("server", "kind", "pid")
    assert_equal "Ruby #{RUBY_VERSION}", fields["runtime"]
    assert header.ascii_only?
    assert_equal :bearer, sent[:auth]
  end

  def test_the_default_name_is_the_machines
    refute_empty core.server_name
  end

  def test_the_switches_headers_and_flags_are_read
    made = core
    answer = { "v" => 1, "modules" => { "errors" => false }, "sync" => 10, "flags" => { "f" => { "on" => true } },
               "headers" => [["X-Frame-Options", "DENY"], ["Bad\nName", "x"], ["X-Evil", "a\r\nb"], "nonsense"] }
    made.define_singleton_method(:request) { |*_, **_| SiteGoose::Response.new(200, { "etag" => '"1"' }, JSON.generate(answer)) }
    assert_equal 30, made.sync_switches, "at least 30 seconds"
    refute made.on?("errors")
    assert made.on?("firewall")
    assert_equal({ "f" => { "on" => true } }, made.flags)
    assert_equal [["X-Frame-Options", "DENY"]], made.security_headers
  end

  def test_sending_to_a_collector
    collector = FakeCollector.new.start
    made = SiteGoose::Core.new("a" * 24, "s3cret", collector.endpoint)
    res = made.request("errors", "/events/server-errors", body: { "errors" => [] })
    assert_equal 202, res.status
    seen = collector.requests("/events/server-errors")[0]
    assert_equal ["a" * 24, "s3cret"], seen["body"].values_at("site_id", "sitesecret")
    assert_equal "analytics-platform-ruby/#{SiteGoose::VERSION}", seen["headers"]["user-agent"]
    made.request("firewall", "/events/firewall/rules?site_id=x", method: "GET", auth: :bearer)
    assert_equal "Bearer s3cret", collector.requests("/events/firewall/rules")[0]["headers"]["authorization"]
    collector.stop
    assert_nil made.request("errors", "/events/server-errors", body: {}), "unreachable: nil, never a raise"
  end

  def test_an_invalid_site_sends_nothing
    assert_nil SiteGoose::Core.new("nope", "s", "http://x").request("core", "/x")
  end
end

class ForkTest < Minitest::Test
  def child_says
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      # What the middleware and jobs do first: on Ruby 3.1+ the fork hook has
      # already run (a no-op); on 3.0 this is how a child finds out.
      SiteGoose::Forking.check
      writer.write(yield ? "1" : "0")
      writer.close
      exit!(0)
    end
    writer.close
    Process.wait(pid)
    reader.read == "1"
  ensure
    reader&.close
  end

  def test_a_job_runs_again_in_a_forked_child
    ran = Queue.new
    job = SiteGoose::Periodic.new(0) { ran << Process.pid; 3600 }
    ran.pop
    assert child_says {
      job.thread.alive? && !job.stopped? && Timeout.timeout(2) { ran.pop } == Process.pid
    }, "the child's own thread runs the job"
  ensure
    job&.stop
  end

  def test_a_fork_waits_for_a_send_in_flight_and_the_child_can_send
    skip "needs Process._fork (Ruby 3.1+)" unless Process.respond_to?(:_fork)
    sending = Queue.new
    ended = nil
    thread = Thread.new do
      SiteGoose::Forking.sending do
        sending << true
        sleep 0.3
        ended = SiteGoose.clock
      end
    end
    sending.pop
    reader, writer = IO.pipe
    pid = fork do
      SiteGoose::Forking.sending { writer.write(SiteGoose.clock.to_s) }
      exit!(0)
    end
    writer.close
    Process.wait(pid)
    forked_at = reader.read.to_f
    thread.join
    assert_operator forked_at, :>=, ended, "the fork came after the send ended"
  end

  def test_queues_are_the_parents_to_send
    core = FakeCore.new
    perf = SiteGoose::Performance.new(core)
    perf.record("GET", "/x", 200, 1.0)
    assert child_says { perf.rows.empty? }
    assert_equal 1, perf.rows.size
  end
end
