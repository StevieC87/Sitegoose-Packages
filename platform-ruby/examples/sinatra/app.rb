# frozen_string_literal: true

# A Sinatra app with the platform in front of it: run with `bundle exec rackup`
# and ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT set.

require "sinatra/base"
require "json"
require "sitegoose"

class Shop < Sinatra::Base
  set :show_exceptions, false
  set :raise_errors, false

  helpers do
    def platform
      SiteGoose.platform
    end
  end

  get "/" do
    proxy = platform&.proxy
    <<~HTML
      <!doctype html><title>Shop</title><h1>Shop</h1>
      <script async src="#{proxy&.script_url}" data-siteid="#{ENV['ANALYTICS_SITE_ID']}" data-collect="#{proxy&.collect_url}"></script>
    HTML
  end

  get "/orders/:id" do
    content_type :json
    JSON.generate(id: params[:id])
  end

  post "/orders" do
    order_id = rand(1000)
    SiteGoose.add_breadcrumb("Order #{order_id} saved")
    SiteGoose.track("purchase", { "numeric_value" => "49.90", "currency" => "EUR", "event_uid" => "order-#{order_id}" },
                            session_id: platform&.session_id(request).to_s)
    content_type :json
    JSON.generate(id: order_id)
  end

  post "/login" do
    platform&.login_failed(request) unless params[:password] == "right"
    halt 401, "no"
  end

  get "/boom" do
    raise ArgumentError, "the payment provider said no"
  end
end
