# frozen_string_literal: true

require "rails/railtie"

module SiteGoose
  # Rails: the middleware first in the stack, the options from (lowest
  # first) the environment, credentials (sitegoose:), the Rails
  # config (config.sitegoose) and SiteGoose.configure in an
  # initializer. Then, on their own: Rails.error reports (Rails.error.handle,
  # .record, .report: the errors your code handles), Rails.logger with
  # errors: {capture_logging: true}, Devise's failed logins (bot protection)
  # and its logins and logouts (audit log), and the controller, mailer and job
  # steps before an error (its breadcrumbs).
  class Railtie < ::Rails::Railtie
    config.sitegoose = ActiveSupport::OrderedOptions.new

    initializer "sitegoose.middleware" do |app|
      app.config.middleware.insert_before 0, SiteGoose::Middleware
    end

    config.after_initialize do |app|
      SiteGoose::RailsSetup.run(app)
    end
  end

  module RailsSetup
    module_function

    def run(app)
      credentials = begin
        given = app.credentials.sitegoose
        given.respond_to?(:to_h) ? given.to_h : {}
      rescue StandardError
        {}
      end
      from_config = app.config.sitegoose.respond_to?(:to_h) ? app.config.sitegoose.to_h : {}
      SiteGoose.defaults(**SiteGoose.symbolize(credentials).merge(SiteGoose.symbolize(from_config)))
      subscribe_errors
      SiteGoose.when_made { |made| hook_logger(made) }
      subscribe_steps
      hook_warden
    end

    def subscribe_errors
      return unless ::Rails.respond_to?(:error) && ::Rails.error.respond_to?(:subscribe)

      ::Rails.error.subscribe(ErrorSubscriber.new)
    end

    def hook_logger(made)
      return unless made.errors&.capture_logging && ::Rails.logger

      made.capture_logger(::Rails.logger)
    end

    # Public notifications only: which controller action ran, which mail
    # went out, which job was queued. Never their contents.
    def subscribe_steps
      return unless defined?(::ActiveSupport::Notifications)

      ::ActiveSupport::Notifications.subscribe("start_processing.action_controller") do |*, payload|
        Context.add_breadcrumb("#{payload[:controller]}##{payload[:action]}") if payload.is_a?(Hash)
      end
      ::ActiveSupport::Notifications.subscribe("deliver.action_mailer") do |*, payload|
        Context.add_breadcrumb("Mail sent: #{payload[:mailer]}") if payload.is_a?(Hash) && payload[:mailer]
      end
      ::ActiveSupport::Notifications.subscribe("enqueue.active_job") do |*, payload|
        job = payload.is_a?(Hash) ? payload[:job] : nil
        Context.add_breadcrumb("Job queued: #{job.class.name}") if job
      end
    rescue StandardError
      nil
    end

    # Devise (Warden): a failed sign-in counts for bot protection, as
    # Django's do in the Python package; sign-ins and sign-outs go in the
    # audit log.
    def hook_warden
      return unless defined?(::Warden::Manager)

      ::Warden::Manager.before_failure do |env, opts|
        if %i[invalid not_found_in_database].include?(opts.is_a?(Hash) ? opts[:message] : nil)
          SiteGoose.platform&.login_failed(env)
        end
      rescue StandardError
        nil
      end
      ::Warden::Manager.after_authentication do |user, auth, _opts|
        SiteGoose.platform&.audit("user.login", actor: RailsSetup.actor(user), request: auth.env)
      rescue StandardError
        nil
      end
      ::Warden::Manager.before_logout do |user, auth, _opts|
        SiteGoose.platform&.audit("user.logout", actor: RailsSetup.actor(user), request: auth.env) if user
      rescue StandardError
        nil
      end
    end

    def actor(user)
      %i[email username login name].each do |field|
        value = user.respond_to?(field) ? user.public_send(field) : nil
        return value.to_s unless value.nil? || value.to_s.empty?
      end
      user.respond_to?(:id) ? user.id.to_s : ""
    end
  end

  # Rails.error's subscriber: what your code handles (Rails.error.handle,
  # .record, .report) is sent. An unhandled error Rails reports from inside a
  # request or job is left to the middleware or the job integration, which
  # know its status and whether it will be retried.
  class ErrorSubscriber
    def report(error, handled: true, severity: :error, context: {}, source: nil, **_rest)
      return if severity.to_s == "info" || !error.is_a?(Exception)
      return if error.instance_variable_defined?(:@__sitegoose_skip)
      return if !handled && Context.request

      SiteGoose.platform&.capture_exception(error, kind: handled ? "handled" : "error")
    rescue StandardError
      nil
    end
  end
end
