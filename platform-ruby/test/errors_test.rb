# frozen_string_literal: true

# The errors module: an error is sent once however many handlers see it, a
# logged exception is sent when asked, a request's route follows errors
# captured without it, a failed batch is tried once more and then waits in a
# file, and the backtrace is in the shape the collector reads.

require_relative "test_helper"
require "tmpdir"

def events_of(core)
  core.sent.flat_map { |s| s[:body]["errors"] }
end

def errors_module(core = FakeCore.new, **options)
  SiteGoose::Errors.new(core, spool_dir: false, **options)
end

def raised(error)
  raise error
rescue StandardError => e
  e
end

class ErrorsTest < Minitest::Test
  def setup
    @retry = SiteGoose::Errors.retry_after
    SiteGoose::Errors.retry_after = 0
  end

  def teardown
    SiteGoose::Errors.retry_after = @retry
  end

  def test_one_error_is_sent_once
    core = FakeCore.new
    errors = errors_module(core)
    error = raised(ArgumentError.new("payment failed"))
    errors.capture_exception(error, status: 500, kind: "error")
    errors.capture_exception(error)
    errors.capture_exception(ArgumentError.new("payment failed"))
    errors.close
    assert_equal 2, events_of(core).size
  end

  def test_the_event
    core = FakeCore.new
    errors = errors_module(core, server_name: "web-1", release: "v1.2 (beta)!")
    errors.capture_exception(raised(KeyError.new("no such key")), status: 502,
                                                                   request: { "method" => "POST", "path" => "/orders/12?x=1", "session_id" => "s1" })
    errors.close
    event = events_of(core)[0]
    assert_equal ["no such key", "KeyError", "handled", 502, "Ruby", RUBY_VERSION, "web-1", "v1.2beta"],
                 event.values_at("message", "error_type", "kind", "status_code", "runtime", "runtime_version", "server_name", "release")
    assert_equal ["POST", "/orders/12", "/orders/:id", "s1"], event.values_at("method", "path", "route", "session_id")
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\z/, event["at"])
    assert_equal "/events/server-errors", core.sent[0][:path]
    assert_equal :body, core.sent[0][:auth]
  end

  # expresscollect/utils/jsError.js reads Ruby frames with this pattern; the
  # first one outside the gems is the site's own code.
  RUBY_FRAME = /^\s*(?:from\s+)?(.+?):(\d+):in [`'](.+)'\s*$/.freeze

  def test_the_backtrace_is_in_the_collectors_ruby_shape
    errors = errors_module(root: __dir__)
    inner = raised(IOError.new("disk"))
    error = begin
      begin
        raise inner
      rescue IOError
        raise "outer failure"
      end
    rescue RuntimeError => e
      e
    end
    stack = errors.stack_of(error)
    lines = stack.split("\n")
    assert_equal "RuntimeError: outer failure", lines[0]
    frames = lines.grep(RUBY_FRAME)
    refute_empty frames
    first = frames[0].match(RUBY_FRAME)
    assert_equal "errors_test.rb", first[1], "made relative to the root"
    assert_includes stack, "Caused by: IOError: disk"
  end

  def test_the_current_request_fills_in_an_error_captured_without_one
    core = FakeCore.new
    errors = errors_module(core)
    SiteGoose::Context.with(-> { { "method" => "POST", "path" => "/orders/12", "route" => "/orders/:id" } }) do
      SiteGoose::Context.add_breadcrumb("Order saved")
      errors.capture_exception(raised(ArgumentError.new("deep inside")))
    end
    SiteGoose::Context.add_breadcrumb("dropped: outside a request")
    errors.capture_exception(raised(ArgumentError.new("outside")))
    errors.close
    inside, outside = events_of(core)
    assert_equal ["/orders/:id", "POST"], inside.values_at("route", "method")
    assert_equal "Order saved", inside["breadcrumbs"][0]["text"]
    assert_equal "note", inside["breadcrumbs"][0]["type"]
    refute outside.key?("route")
    refute outside.key?("breadcrumbs")
  end

  def test_the_trail_keeps_the_last_fifteen_steps
    SiteGoose::Context.with({}) do
      20.times { |i| SiteGoose::Context.add_breadcrumb("step #{i}") }
      crumbs = SiteGoose::Context.breadcrumbs
      assert_equal 15, crumbs.size
      assert_equal "step 19", crumbs[-1]["text"]
    end
  end

  def test_a_failed_batch_is_sent_once_more_and_only_once
    [[[503, 503], 2], [[nil, 202], 2], [[400], 1]].each do |answers, expected|
      core = FakeCore.new(answers: answers.dup)
      errors = errors_module(core)
      errors.capture_exception(ArgumentError.new("x"))
      errors.flush
      assert_equal expected, core.sent.size, answers.inspect
    end
  end

  def test_an_exception_logged_then_raised_keeps_the_frameworks_status_and_request
    core = FakeCore.new
    errors = errors_module(core)
    error = raised(ArgumentError.new("card declined"))
    errors.capture_exception(error, kind: "logged")
    errors.capture_exception(error, status: 500, kind: "error", request: { "method" => "POST", "path" => "/pay" })
    errors.close
    sent = events_of(core)
    assert_equal 1, sent.size
    assert_equal ["error", 500, "POST", "/pay", "/pay"], sent[0].values_at("kind", "status_code", "method", "path", "route")
  end

  def test_before_send_can_change_or_drop
    core = FakeCore.new
    errors = errors_module(core, before_send: lambda { |event, error|
      next nil if error.message == "drop"

      event.merge("message" => "changed")
    })
    errors.capture_exception(ArgumentError.new("drop"))
    errors.capture_exception(ArgumentError.new("keep"))
    errors.close
    assert_equal ["changed"], events_of(core).map { |e| e["message"] }
  end

  def test_switched_off_in_the_dashboard_nothing_is_sent
    core = FakeCore.new
    core.switches = { "errors" => false }
    errors = errors_module(core)
    errors.capture_exception(ArgumentError.new("x"))
    errors.close
    assert_empty core.sent
  end

  def test_what_cannot_be_sent_waits_in_a_file_and_goes_later
    Dir.mktmpdir do |dir|
      core = FakeCore.new(answers: [503, 503], valid: false)
      errors = SiteGoose::Errors.new(core, spool_dir: dir)
      # A core that isn't valid keeps no file; give it one as a valid core would.
      errors.instance_variable_set(:@spool_file, File.join(dir, "analytics-errors-test.jsonl"))
      errors.capture_exception(ArgumentError.new("while the collector was away"))
      errors.flush
      waiting = File.readlines(errors.spool_file)
      assert_equal 1, waiting.size
      assert_equal "600", format("%o", File.stat(errors.spool_file).mode & 0o777)
      refute_includes waiting[0], "sitesecret", "credentials are added when sent, never written down"
      errors.resend
      refute File.exist?(errors.spool_file)
      assert_equal "while the collector was away", core.sent[-1][:body]["errors"][0]["message"]
    end
  end

  def test_a_logger_given_an_exception_sends_it_and_still_logs
    made = quiet_platform(errors: { spool_dir: false })
    out = StringIO.new
    logger = made.capture_logger(Logger.new(out))
    logger.error(raised(ArgumentError.new("card declined")))
    logger.error("plain text is not sent")
    logger.warn(raised(ArgumentError.new("a warning is not sent")))
    queued = made.errors.queue
    assert_equal ["card declined"], queued.map { |e| e["message"] }
    assert_equal "logged", queued[0]["kind"]
    assert_includes out.string, "card declined"
    made.close
  end

  def test_the_exception_that_ends_the_program_is_sent
    core = FakeCore.new
    errors = errors_module(core)
    errors.capture_exit(raised(RuntimeError.new("crash")))
    errors.capture_exit(SystemExit.new(0))
    assert_equal ["crash"], events_of(core).map { |e| e["message"] }
    assert_equal "error", events_of(core)[0]["kind"]
  end

  def test_a_frozen_or_odd_error_never_raises
    core = FakeCore.new
    errors = errors_module(core)
    errors.capture_exception(ArgumentError.new("frozen").freeze)
    errors.capture_exception("a string")
    bad = Class.new(StandardError) { def message = raise("no message") }
    errors.capture_exception(bad.new)
    errors.capture_exception(ArgumentError.new("\xff binary".b))
    errors.close
    assert_equal ["frozen", "a string", "\uFFFD binary"], events_of(core).map { |e| e["message"] }
    JSON.generate(core.sent)
  end
end
