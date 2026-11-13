# frozen_string_literal: true

# The security headers taken from the platform config, against the cases every
# client shares: sdk/protocols/header-cases.json. Only the nine the dashboard
# can produce get through, so all the packages add the same ones.

require_relative "test_helper"

class HeaderSharedCasesTest < Minitest::Test
  CASES = shared("header-cases.json")["cases"]

  def test_shared_cases
    CASES.each do |c|
      value = c["value"] * (c["repeat"] || 1)
      assert_equal c["ok"], SiteGoose::Core.safe_header?([c["name"], value]), "#{c["name"].inspect}: #{c["value"][0, 40].inspect}"
    end
  end

  def test_only_pairs_of_strings
    [nil, "X-Frame-Options", ["X-Frame-Options"], ["X-Frame-Options", 1], ["X-Frame-Options", "DENY", "x"]].each do |pair|
      refute SiteGoose::Core.safe_header?(pair), pair.inspect
    end
  end
end
