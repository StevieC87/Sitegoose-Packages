# frozen_string_literal: true

require_relative "app"

# First, so it sees every request; the options come from the environment
# (ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET, ANALYTICS_ENDPOINT) or are given here.
use SiteGoose::Middleware
run Shop
