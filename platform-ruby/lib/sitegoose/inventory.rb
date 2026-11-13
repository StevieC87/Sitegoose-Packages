# frozen_string_literal: true

# Software inventory module (protocol in sdk/protocols/inventory.md): the
# gems the app runs and its Ruby version, sent to POST /events/inventory a
# minute after start and then once a day (the collector's `every`), so the
# Security check can match them against known security holes (OSV's
# "RubyGems" ecosystem). Runs in a background thread, never in a request;
# names and versions only.
#
# Where the list comes from: the gems loaded in this process (Bundler's, so
# what Gemfile.lock pins and the groups the app runs with), each marked
# `direct` when the Gemfile asks for it by name. With no Bundler (a plain
# `ruby app.rb`), Gemfile.lock next to the app is read instead.

module SiteGoose
  class Inventory
    FIRST = 60
    RETRY_EVERY = 60 * 60
    EVERY = 24 * 60 * 60
    MAX_PACKAGES = 5000
    ECOSYSTEM = "RubyGems"

    # "    rack (3.1.8)" and "    nokogiri (1.16.7-x86_64-linux)" under a
    # GEM, GIT or PATH section's specs, as [name, version].
    def self.lockfile_specs(text)
      found = {}
      in_specs = false
      text.to_s.each_line do |line|
        if line.match?(/\A\S/)
          in_specs = false
        elsif line.match?(/\A  specs:\s*\z/)
          in_specs = true
        elsif in_specs && (m = /\A {4}([^\s(]+) \(([^)]+)\)\s*\z/.match(line))
          version = m[2].split("-", 2)[0]
          found[m[1]] ||= version
        end
      end
      found
    end

    # The Gemfile's own dependencies, by name, from a Gemfile.lock's DEPENDENCIES.
    def self.lockfile_direct(text)
      names = {}
      in_deps = false
      text.to_s.each_line do |line|
        if line.match?(/\A\S/)
          in_deps = line.start_with?("DEPENDENCIES")
        elsif in_deps && (m = /\A {2}([^\s!(]+)/.match(line))
          names[m[1]] = true
        end
      end
      names
    end

    def self.bundler_direct
      return {} unless defined?(::Bundler) && ::Bundler.respond_to?(:definition)

      ::Bundler.definition.dependencies.to_h { |dep| [dep.name, true] }
    rescue StandardError, ScriptError
      {}
    end

    # [{"ecosystem", "name", "version", "direct"?}], one per gem, sorted by name.
    def self.installed_packages(root = nil)
      specs = {}
      direct = {}
      if defined?(::Gem) && ::Gem.respond_to?(:loaded_specs)
        ::Gem.loaded_specs.each_value do |spec|
          name = spec.name.to_s
          version = spec.version.to_s
          specs[name] ||= version unless name.empty? || version.empty?
        end
        direct = bundler_direct
      end
      if specs.size <= 1
        lock = File.join((root || Dir.pwd).to_s, "Gemfile.lock")
        if File.file?(lock)
          text = File.read(lock, encoding: "UTF-8")
          specs = lockfile_specs(text).merge(specs)
          direct = lockfile_direct(text) if direct.empty?
        end
      end
      specs.sort_by { |name, _| name.downcase }.map do |name, version|
        row = { "ecosystem" => ECOSYSTEM, "name" => name, "version" => version.delete_prefix("v") }
        row["direct"] = true if direct[name]
        row
      end
    rescue StandardError
      []
    end

    # Options: host (the server's name; default the host name), root (where
    # Gemfile.lock is when Bundler isn't loaded; default the working directory).
    def initialize(core, host: nil, root: nil, **_)
      @core = core
      @root = root
      @host = SiteGoose.text(host.nil? ? SiteGoose.hostname : host).gsub(/[^A-Za-z0-9._-]/, "-")[0, 100]
      @host = "server" if @host.empty?
      @job = core.valid? ? Periodic.new(FIRST) { report } : nil
    end

    def body
      packages = Inventory.installed_packages(@root)
      {
        "site_id" => @core.site_id,
        "host" => @host,
        "at" => SiteGoose.iso_now,
        "runtime" => { "ruby" => RUBY_VERSION },
        "packages" => packages.first(MAX_PACKAGES),
        "truncated" => packages.size > MAX_PACKAGES
      }
    end

    def report
      return RETRY_EVERY unless @core.on?("inventory")

      res = @core.request("inventory", "/events/inventory", auth: :bearer, body: body)
      return RETRY_EVERY if res.nil? || !res.ok?

      answer = res.json
      every = answer.is_a?(Hash) ? answer["every"] : nil
      every.is_a?(Integer) && every.positive? ? [RETRY_EVERY, every].max : EVERY
    end

    def flush; end

    def close
      @job&.stop
    end
  end
end
