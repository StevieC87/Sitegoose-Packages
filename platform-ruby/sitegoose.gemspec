# frozen_string_literal: true

require_relative "lib/sitegoose/version"

Gem::Specification.new do |spec|
  spec.name = "sitegoose"
  spec.version = SiteGoose::VERSION
  spec.authors = ["steviec87"]
  spec.homepage = "https://sitegoose.com"
  spec.summary = "Firewall, error monitoring and server analytics for your Ruby server, run from your SiteGoose dashboard."
  spec.description = "Rack middleware and a Railtie: a firewall with rate limits, shared blocks, attack patterns and a " \
                     "browser check; error monitoring (Rails.error, Sidekiq); server speed per route, with its database queries, " \
                     "outgoing calls, job queues and how close the server is to its limits; crawler counts; " \
                     "server-side events, leads and audit log; feature flags and maintenance mode; and the gems, " \
                     "settings and machine figures the Security check needs. Standard library and rack only."
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0"
  spec.files = Dir["lib/**/*.rb"] + %w[README.md LICENSE]
  spec.require_paths = ["lib"]
  spec.add_dependency "rack", ">= 2.0", "< 4"
  spec.metadata = { "rubygems_mfa_required" => "true" }
end
