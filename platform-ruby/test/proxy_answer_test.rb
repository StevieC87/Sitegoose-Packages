# frozen_string_literal: true

# The type a collector answer is served with from the site's own domain,
# against the cases every client shares: sdk/protocols/proxy-answer-cases.json.

require_relative "test_helper"

class ProxyAnswerSharedCasesTest < Minitest::Test
  CASES = shared("proxy-answer-cases.json")["cases"]

  def test_shared_cases
    CASES.each do |c|
      assert_equal c["served"], SiteGoose::Proxy.answer_type(c["type"]), c["type"].inspect
    end
  end
end
