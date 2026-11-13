# frozen_string_literal: true

# How the server is set up (protocol in sdk/protocols/posture.md): the
# settings that leave the app open (Rails', when it's a Rails app), whether it
# runs as root, code anyone on the machine can write, and files in the folders
# it serves to the web that should never be public. Sent to POST
# /events/posture a few minutes after start and then once a day (the
# collector's `every`), so Security -> Security check can say what to change.
#
# It only reads: nothing here changes a setting, a permission or a file, and
# no file's contents are sent -- paths, sizes, times and short values only.
# The walk is bounded and runs in a background thread, never in a request;
# with no folder served to the web there is nothing to walk and only the
# settings are reported.

module SiteGoose
  class Posture
    FIRST = 180
    RETRY_EVERY = 60 * 60
    EVERY = 24 * 60 * 60
    MAX_CHECKS = 200
    MAX_EXPOSURE = 50
    MAX_ENTRIES = 20_000
    MAX_DEPTH = 6
    MAX_PERM_CHECKS = 3000
    SKIP_DIRS = %w[.git .svn .hg node_modules vendor cache .cache .history __pycache__].freeze
    VCS_DIRS = %w[.git .svn .hg .bzr].freeze
    CODE_FILE = /\.(py|pyw|js|cjs|mjs|php[0-9]?|phtml|rb|erb|pl|sh)\z/i.freeze
    # Files that shouldn't be downloadable, by name; first match wins.
    EXPOSURE = [
      ["database_dump", /\.sql(\.(gz|bz2|xz|zip))?\z/i],
      ["private_key", /\A(id_rsa|id_dsa|id_ecdsa|id_ed25519)\z|\.(pem|key|p12|pfx|jks)\z/i],
      ["env", /\A\.env(\z|\.)|\Aenv\.(ini|txt)\z/i],
      ["archive", /\.(zip|tar|tgz|tar\.gz|tar\.bz2|rar|7z)\z/i],
      ["backup", /\.(bak|old|orig|save|swp|copy|backup)\z|~\z|\.(py|rb|yml|json|conf|config|ini|ya?ml)\.(bak|old|orig|save|txt)\z/i],
      ["info", /\A(phpinfo|info|adminer)\.php\z/i],
      ["log", /\A(debug|error|access)[-_.]?log\z|\.log\z/i]
    ].freeze
    # What a secret looks like when nobody set one.
    INSECURE_KEYS = %w[changeme secret your-secret-key put-your-secret-key-here].freeze

    def self.kind_of(name)
      EXPOSURE.each { |kind, pattern| return kind if pattern.match?(name) }
      nil
    end

    # A folder inside another folder on the list is already covered: without
    # this, every file under it would be reported twice.
    def self.without_nested(roots)
      unique = {}
      roots.each { |root| unique[root["dir"]] ||= root }
      unique.values.reject do |root|
        unique.keys.any? { |other| other != root["dir"] && "#{root['dir']}/".start_with?("#{other}/") }
      end
    end

    # [{"dir", "prefix"}]: prefix is where the web serves the folder, so the
    # path we report is the one the dashboard can ask the site for. Not told:
    # Rails' public/ (served at /), when it's a Rails app and it's there.
    def self.roots_of(given)
      roots = []
      Array(given).each do |entry|
        folder = entry.is_a?(Hash) ? (entry[:dir] || entry["dir"]) : entry
        next if folder.nil? || folder.to_s.empty?

        prefix = entry.is_a?(Hash) ? (entry[:prefix] || entry["prefix"]).to_s.gsub(%r{\A/+|/+\z}, "") : ""
        roots << { "dir" => File.expand_path(folder.to_s), "prefix" => prefix }
      end
      return without_nested(roots) unless roots.empty?

      folder = rails_public
      roots << { "dir" => File.expand_path(folder), "prefix" => "" } if folder && File.directory?(folder)
      without_nested(roots)
    end

    def self.rails_app
      return nil unless defined?(::Rails) && ::Rails.respond_to?(:application) && ::Rails.application

      ::Rails.application
    rescue StandardError
      nil
    end

    def self.rails_public
      return nil unless rails_app

      ::Rails.public_path.to_s
    rescue StandardError
      nil
    end

    def self.check(checks, id, failed, value = nil)
      row = { "id" => id, "state" => failed.nil? ? "unknown" : (failed ? "fail" : "pass") }
      row["value"] = value.to_s[0, 200] if value && !value.to_s.empty?
      checks << row
    end

    # The Rails settings that decide how much a hole in the site is worth.
    def self.rails_checks
      app = rails_app
      return [] unless app

      config = app.config
      checks = []
      env = ::Rails.env.to_s
      check(checks, "app.rails_env", env != "production", env)
      # Full error pages, with code and backtraces, for every visitor.
      check(checks, "app.rails_debug", config.consider_all_requests_local ? true : false)
      key = begin
        app.secret_key_base.to_s
      rescue StandardError
        nil
      end
      check(checks, "app.secret_key", key.nil? ? nil : (key.size < 32 || INSECURE_KEYS.any? { |mark| key.downcase.include?(mark) }))
      hosts = config.respond_to?(:hosts) ? Array(config.hosts) : nil
      unless hosts.nil?
        # An empty list switches host checking off: any Host header is served.
        shown = hosts.first(10).map { |h| h.respond_to?(:source) ? h.source : h.to_s }
        check(checks, "app.allowed_hosts", hosts.empty? || hosts.any? { |h| h.to_s == "*" }, shown.join(", "))
      end
      session = config.respond_to?(:session_options) ? (config.session_options || {}) : {}
      check(checks, "app.session_cookie_httponly", session[:httponly] == false)
      # Cookie flags only matter once the site is on HTTPS, which these say it is.
      force_ssl = config.respond_to?(:force_ssl) && config.force_ssl ? true : false
      if force_ssl || session[:secure]
        check(checks, "app.session_cookie_secure", !(force_ssl || session[:secure]))
        check(checks, "app.https_redirect", !force_ssl)
      end
      checks
    rescue StandardError
      checks || []
    end

    def self.app_checks
      checks = rails_checks
      # Running the web app as root turns any hole in it into the whole machine.
      check(checks, "server.runs_as_root", Process.uid.zero?) if Process.respond_to?(:uid)
      checks
    end

    # One bounded walk per root: [exposure, writable or nil, examples, truncated].
    def self.walk(roots)
      exposure = []
      examples = []
      writable = checked = entries = 0
      roots.each do |root|
        queue = [[root["dir"], 0]]
        until queue.empty?
          folder, depth = queue.shift
          names = begin
            Dir.children(folder)
          rescue SystemCallError
            next
          end
          names.each do |name|
            entries += 1
            return [exposure, checked.positive? ? writable : nil, examples, true] if entries > MAX_ENTRIES

            path = File.join(folder, name)
            info = begin
              File.lstat(path)
            rescue SystemCallError
              next
            end
            next if info.symlink?

            relative = [root["prefix"], path.delete_prefix("#{root['dir']}/")].reject(&:empty?).join("/")
            if info.directory?
              if VCS_DIRS.include?(name)
                exposure << { "path" => "#{relative}/config", "kind" => "vcs" } if exposure.size < MAX_EXPOSURE
                next
              end
              queue << [path, depth + 1] if depth + 1 <= MAX_DEPTH && !SKIP_DIRS.include?(name)
              next
            end
            next unless info.file?

            kind = kind_of(name)
            if kind && exposure.size < MAX_EXPOSURE
              exposure << { "path" => relative, "kind" => kind, "size" => info.size, "mtime" => info.mtime.utc.iso8601(3) }
            end
            next unless checked < MAX_PERM_CHECKS && CODE_FILE.match?(name)

            checked += 1
            if info.world_writable?
              writable += 1
              examples << relative if examples.size < 3
            end
          end
        end
      end
      [exposure, checked.positive? ? writable : nil, examples, false]
    end

    # Options: roots (the folders the web serves, as "public" or
    # {dir: ..., prefix: "assets"}; default: Rails' public/), host (the
    # server's name), checks (a callable returning more checks of your own).
    def initialize(core, roots: nil, host: nil, checks: nil, **_)
      @core = core
      @given = roots
      @roots = nil
      @extra = checks
      @host = SiteGoose.text(host.nil? ? SiteGoose.hostname : host).gsub(/[^A-Za-z0-9._-]/, "-")[0, 100]
      @host = "server" if @host.empty?
      @job = core.valid? ? Periodic.new(FIRST) { send_report } : nil
    end

    # Worked out on first use, once the app (Rails above all) has booted.
    def roots
      @roots ||= Posture.roots_of(@given)
    end

    # What would be reported now (also used by the job and by tests).
    def report
      exposure, writable, examples, truncated = Posture.walk(roots)
      checks = Posture.app_checks
      unless writable.nil?
        row = { "id" => "server.code_writable", "state" => writable.positive? ? "fail" : "pass" }
        row["value"] = "#{writable} files, e.g. #{examples.join(', ')}" if writable.positive?
        checks << row
      end
      begin
        extra = @extra.respond_to?(:call) ? @extra.call : []
        Array(extra).each do |c|
          next unless c.is_a?(Hash)

          c = c.to_h { |k, v| [k.to_s, v] }
          next unless c["id"] && %w[pass fail unknown].include?(c["state"].to_s)

          row = { "id" => c["id"].to_s.downcase[0, 60], "state" => c["state"].to_s }
          row["value"] = c["value"].to_s[0, 200] if c["value"]
          checks << row
        end
      rescue StandardError
        nil
      end
      body = {
        "site_id" => @core.site_id,
        "host" => @host,
        "at" => SiteGoose.iso_now,
        "checks" => checks.first(MAX_CHECKS),
        "facts" => { "agent" => "ruby/#{RUBY_VERSION}" }
      }
      unless roots.empty?
        # Left out when there's no folder to walk: the dashboard then says
        # this wasn't checked, instead of taking an empty walk for a clean one.
        body["exposure"] = exposure.first(MAX_EXPOSURE)
        body["facts"]["webroot"] = roots[0]["dir"][0, 100]
      end
      body["truncated"] = true if truncated
      body
    end

    def send_report
      # The set-up checks ride the software inventory switch.
      return RETRY_EVERY unless @core.on?("inventory")

      res = @core.request("posture", "/events/posture", auth: :bearer, body: report)
      return RETRY_EVERY if res.nil? || !res.ok?

      answer = res.json
      every = answer.is_a?(Hash) && answer["every"].is_a?(Integer) && answer["every"].positive? ? answer["every"] : EVERY
      [RETRY_EVERY, every].max
    end

    def flush; end

    def close
      @job&.stop
    end
  end
end
