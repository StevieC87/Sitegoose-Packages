# frozen_string_literal: true

# The modules with little of their own: forms, audit, flags, maintenance and
# the security headers.

require "securerandom"

module SiteGoose
  # Form protection module: checks a form your server received before you
  # accept it (POST /collectanalytics/shield/verify, the same check as spam
  # protection's). It reads the hidden "analytics-shield" answer the tracker
  # puts in protected forms, and checks the email, name and text for fake
  # sign-ups. Spam lands in the site's spam folder (Leads -> Spam). Passwords,
  # card numbers and tokens are never sent. Fails open: when the check can't
  # be made, the form is accepted (checked false).
  class Forms
    # Fields never sent, by name. Whoever adds the check to a sign-up or a
    # checkout relies on this list: keep it wide. (pass also covers passwd
    # and passport, cc[-_]? the browsers' autocomplete names cc-number,
    # cc-csc and cc-exp.) The same list in every package; (?a) makes \b
    # ASCII, as PHP's and Python's are.
    PRIVATE_FIELD = /(?a)pass|pwd|card|cc[-_]?(num|no|number|csc|exp)|cvc|cvv|cvn|expiry|exp[-_]?(month|year|date)|secret|token|\bauth\b|authoriz|api[-_]?key|otp|mfa|2fa|\bpin\b|security[-_]?code|signature|private|ssn|sin\b|nino|tax[-_]?id|iban|bic|swift|routing|account[-_]?(no|num|number)|dob|birth|licen[cs]e|csrf|nonce|analytics-shield/i.freeze
    # A card number in a field nobody thought to name "card" still must not
    # be sent, so values are checked too: 13-19 digits that pass Luhn are
    # taken out of the text and the rest of the message is kept, so spam is
    # still judged.
    DIGITS = /(?a)\b(?:\d[ -]?){12,18}\d\b/.freeze
    MAX_FIELDS = 50
    ANSWER = "analytics-shield"

    # Rails and Rack nest "user[email]" as {"user" => {"email" => ...}}: put
    # back as the form named them, so a label is what the visitor saw.
    def self.flat(fields, prefix = nil, out = {}, depth = 0)
      (fields || {}).each do |label, value|
        name = prefix ? "#{prefix}[#{label}]" : label.to_s
        if value.is_a?(Hash)
          flat(value, name, out, depth + 1) if depth < 3
        else
          out[name] = value
        end
        break if out.size >= MAX_FIELDS * 2
      end
      out
    end

    def self.plain_fields(fields)
      out = {}
      flat(fields).first(MAX_FIELDS).each do |label, value|
        next if label.to_s.match?(PRIVATE_FIELD)

        value = value.select { |v| v.is_a?(String) }.join(", ") if value.is_a?(Array)
        out[SiteGoose.text(label, 100)] = without_card_numbers(SiteGoose.text(value, 2000)) if value.is_a?(String)
      end
      out
    end

    # Anything shaped like a card number, and passing Luhn, as [removed].
    # Luhn is what keeps order numbers and phone numbers readable.
    def self.without_card_numbers(text)
      text.gsub(DIGITS) do |match|
        sum = 0
        match.delete("^0-9").reverse.each_char.with_index do |digit, i|
          n = digit.to_i
          n *= 2 if i.odd?
          sum += n > 9 ? n - 9 : n
        end
        (sum % 10).zero? ? "[removed]" : match
      end
    end

    def initialize(core, **_)
      @core = core
    end

    # fields: the form as a hash. -> {ok:, spam:, reasons:, checked:}.
    def check(fields, ip = "", email = nil, name = nil, form = nil)
      return { ok: true, spam: false, reasons: [], checked: false } unless @core.on?("forms")

      unchecked = { ok: true, spam: false, reasons: ["unchecked"], checked: false }
      fields = (fields || {}).to_h { |k, v| [k.to_s, v] }
      token = fields[ANSWER]
      token = token.first if token.is_a?(Array)
      body = { "token" => token.is_a?(String) ? token : "", "fields" => Forms.plain_fields(fields), "ip" => ip.to_s }
      { "email" => email, "name" => name, "form" => form }.each { |k, v| body[k] = v if v.is_a?(String) }
      res = @core.request("forms", "/collectanalytics/shield/verify", body: body)
      if res.nil? || res.status >= 500 || [403, 429].include?(res.status)
        @core.log("forms", "the site secret was refused; forms aren't checked") if res&.status == 403
        return unchecked
      end
      data = res.status == 200 ? res.json : nil
      # A verdict, spam or not, is always a 200 with `success`. Anything else
      # judged nothing, and must not look like protection that works.
      return unchecked unless data.is_a?(Hash) && [true, false].include?(data["success"])

      spam = data["success"] == false
      { ok: !spam, spam: spam, reasons: Array(data["reasons"]), checked: true }
    end

    def flush; end

    def close; end
  end

  # Audit log module: who did what on your site, sent to POST /events/audit
  # in small batches in the background (Security -> Audit log). What goes in
  # (names, emails) is up to you. Devise's logins and logouts are recorded on
  # their own.
  class Audit
    BATCH = 100
    QUEUE_MAX = 1000
    FLUSH_EVERY = 5

    attr_reader :queue

    def initialize(core, **_)
      @core = core
      @queue = []
      @lock = Mutex.new
      @job = core.valid? ? Periodic.new(FLUSH_EVERY) { flush; FLUSH_EVERY } : nil
      Forking.register(self)
    end

    def after_fork_in_child
      @lock = Mutex.new
      @queue = []
    end

    def record(action, actor = "", target = "", details = nil, actor_ip = "", session_id = "")
      return if !@core.on?("audit") || !action.is_a?(String) || action.empty?

      entry = {
        "at" => SiteGoose.iso_now, "action" => action[0, 64], "actor" => SiteGoose.text(actor, 200),
        "target" => SiteGoose.text(target, 300), "details" => details, "actor_ip" => actor_ip.to_s,
        "session_id" => session_id.to_s
      }
      full = @lock.synchronize do
        return if @queue.size >= QUEUE_MAX

        @queue << entry
        @queue.size >= BATCH
      end
      @job&.run_now if full
    end

    def flush
      waiting = @lock.synchronize do
        taken = @queue
        @queue = []
        taken
      end
      waiting.each_slice(BATCH) { |batch| @core.request("audit", "/events/audit", body: { "entries" => batch }) }
    end

    def close
      @job&.stop
      Forking.unregister(self)
      flush
    end
  end

  # Feature flags module: turn features of your app on or off from the
  # dashboard (Site settings -> Server), for everyone, a share of users, or
  # listed user IDs. enabled?() answers from memory; the flags come with the
  # module switches (core), about once a minute.
  class Flags
    # FNV-1a over "key:user", 0-99: the same as the Node, PHP and Python packages.
    def self.bucket(key, user)
      h = 0x811C9DC5
      "#{key}:#{user}".each_byte do |byte|
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
      end
      h % 100
    end

    def self.evaluate(flag, key, user)
      return false unless flag["on"]

      uid = user.nil? ? "" : user.to_s
      return true if !uid.empty? && Array(flag["users"]).map(&:to_s).include?(uid)

      rollout = flag.key?("rollout") ? flag["rollout"].to_i : 100
      return true if rollout >= 100
      return false if rollout <= 0 || uid.empty?

      bucket(key, uid) < rollout
    end

    def initialize(core, **_)
      @core = core
    end

    def enabled?(key, user = nil, default = false)
      flag = @core.on?("flags") ? @core.flags[key.to_s] : nil
      flag.is_a?(Hash) ? Flags.evaluate(flag, key.to_s, user) : default
    rescue StandardError
      default
    end

    def flush; end

    def close; end
  end

  # Maintenance mode module: while it's on (Site settings -> Server), visitors
  # get a "back soon" page (503, so search engines know it's temporary),
  # except allowed addresses and whoever opened the preview link
  # (?site_preview=<code>, remembered for a day in a cookie).
  class Maintenance
    COOKIE = "site_preview"
    ESCAPES = { "&" => "&amp;", "<" => "&lt;", ">" => "&gt;", '"' => "&quot;", "'" => "&#x27;" }.freeze

    def self.escape(text)
      SiteGoose.text(text).gsub(/[&<>"']/, ESCAPES)
    end

    def self.page(message)
      text = escape(message.to_s.empty? ? "We're doing some maintenance. Please check back in a few minutes." : message)
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" \
        "<title>Back soon</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;" \
        "background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}" \
        "p{color:#475569;margin:0}@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}p{color:#94a3b8}}</style></head>" \
        "<body><main><h1>Back soon</h1><p>#{text}</p></main></body></html>"
    end

    def self.query_value(query, name)
      query.to_s.split("&").each do |pair|
        k, v = pair.split("=", 2)
        return RequestRules.decode_once(v.to_s) if RequestRules.decode_once(k.to_s) == name
      end
      ""
    end

    # Options: skip (->(path) { true } lets a request through: health checks).
    def initialize(core, skip: nil, **_)
      @core = core
      @skip = skip
      @allow_for = nil
      @allow = IpSet.new([])
    end

    # nil to let the request through, [:pass, headers] to let it through and
    # remember the preview link, else [status, headers, body].
    # secure: the request came over HTTPS (the cookie is then Secure).
    def decide(ip, path, query, cookie_header, secure: false)
      m = @core.on?("maintenance") ? @core.maintenance : nil
      return nil if !m.is_a?(Hash) || !m["on"] || (@skip && @skip.call(path))

      unless @allow_for.equal?(m["allow"])
        @allow_for = m["allow"]
        @allow = IpSet.new(Array(m["allow"]))
      end
      key = IP.key(ip)
      return nil if key && @allow.has?(key)

      code = m["bypass"].to_s
      unless code.empty?
        if Challenge.secure_compare(Maintenance.query_value(query, COOKIE), code)
          return [:pass, { "set-cookie" => "#{COOKIE}=#{code}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax#{secure ? '; Secure' : ''}" }]
        end
        return nil if Challenge.cookie_values(cookie_header, COOKIE).any? { |value| Challenge.secure_compare(value, code) }
      end
      [503, { "content-type" => "text/html; charset=utf-8", "retry-after" => "600", "cache-control" => "no-store" }, Maintenance.page(m["message"])]
    end

    def flush; end

    def close; end
  end

  # The security headers module: the headers come with the module switches (core).
  class Headers
    def flush; end

    def close; end
  end
end
