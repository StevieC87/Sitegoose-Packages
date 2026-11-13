# frozen_string_literal: true

# The Railtie already put the middleware first in the stack; this gives it its
# options. Or leave this file out and use the credentials
# (sitegoose: site_id, secret, endpoint) or the environment.
SiteGoose.configure(
  site_id: ENV.fetch("ANALYTICS_SITE_ID", "YOUR_SITE_ID"),
  secret: ENV["ANALYTICS_SITE_SECRET"],
  endpoint: ENV.fetch("ANALYTICS_ENDPOINT", "https://YOUR_COLLECTOR_URL"),
  trust_proxy: 1,                          # behind Nginx or a load balancer
  server_name: ENV["ANALYTICS_SERVER_NAME"], # one per service: web, sidekiq, ...
  errors: { capture_logging: true },
  enabled: !Rails.env.test?
)

# Sidekiq: every job timed, its last failed attempt sent.
if defined?(Sidekiq)
  require "sitegoose/sidekiq"
  SiteGoose::Sidekiq.install
end
