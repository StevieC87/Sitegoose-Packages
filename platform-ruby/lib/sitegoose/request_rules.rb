# frozen_string_literal: true

# Request rules (virtual patching; protocol in sdk/protocols/firewall.md):
# the firewall has always matched addresses, these match the request -- its
# method, path, query string and user agent -- so an attack is turned away
# before the vulnerable code runs. They arrive with the other rules and are
# compiled once per fetch; matching is plain string work on text we already
# have, so it costs nothing per request.
#
# The matching is the same in every package: the shared cases are in
# sdk/protocols/request-rules-cases.json, run by test/request_rules_test.rb.
#
# Ruby's ^ and $ are line anchors, unlike JavaScript's and Python's, so a
# pattern's anchors are rewritten to \A and \z before it is compiled: a
# decoded %0a in a path must not end the "line" a rule anchors to.

module SiteGoose
  module RequestRules
    MAX_RULES = 200
    # How much of a part one regex search may look at. Patterns come from our
    # rules, but the text comes from whoever is asking: a bounded slice keeps
    # a bad pattern from being a hung request (and Ruby 3.2+ also times it
    # out). A longer part is searched in windows of MAX_TEXT, each starting
    # WINDOW_STEP after the last, so a match up to 1,000 characters long is
    # found wherever it sits. The plain matchers read the whole part: a part
    # cut short would let filler carry an attack past them.
    MAX_TEXT = 2000
    WINDOW_STEP = 1000
    MAX_REGEX = 200
    SECTIONS = %w[path query ua].freeze
    MATCHERS = %w[exact prefix suffix contains].freeze
    REGEX_TIMEOUT = 0.05
    # What a method override may name (X-HTTP-Method-Override, _method).
    METHOD_TOKEN = /\A[A-Z]{1,20}\z/.freeze

    module_function

    # A pattern can only come from us, but a careless one would be matched
    # against text an attacker chooses. So the client checks the shape itself
    # instead of trusting what it was handed: a repeated group that holds a
    # quantifier or an alternation ("(a+)+", "(a|ab)*"), backreferences and
    # lookbehind are refused, and so is more than one free repeat. The same
    # check as backend/services/firewall/requestRules.js.
    #
    # Group syntax is a list of what is allowed, not of what isn't: only
    # "(?:", "(?=" and "(?!". Ruby (Onigmo) has more than JavaScript and
    # Python -- subexpression calls (\g<1>, \g'x'), named groups and
    # references written with quotes ((?'x'...), \k'x'), absence operators
    # ((?~...)), conditionals ((?(1)...)), inline options -- and a call
    # repeated against an alternation took 51 seconds in a test.
    GROUPS = [":", "=", "!"].freeze
    # Escapes that refer to a group: \1-\9, \g (call), \k (named reference);
    # and \N, which isn't in the shared subset either.
    REFERENCE = /\\(?:[1-9]|[gkN])/.freeze

    def safe_pattern?(pattern)
      return false unless pattern.is_a?(String) && !pattern.empty? && pattern.size <= MAX_REGEX

      open = []
      i = 0
      n = pattern.size
      while i < n
        char = pattern[i]
        if char == "\\"
          return false if pattern[i, 2].match?(REFERENCE)

          i += 2
          next
        end
        if char == "["
          # A character class: skipped whole, quantifiers inside it are literals.
          i += pattern[i] == "\\" ? 2 : 1 while i < n && pattern[i] != "]"
          i += 1
          next
        end
        if char == "("
          open << false
          # "(?:", "(?=", "(?!": that ? names the kind of group, it repeats nothing.
          # "(*": a PCRE verb ("(*FAIL)"), never in the shared subset.
          return false if pattern[i + 1] == "*"

          if pattern[i + 1] == "?"
            return false unless GROUPS.include?(pattern[i + 2])

            i += 2
          end
        elsif "*+?".include?(char) && pattern[i + 1] == "+" && i.positive? && pattern[i - 1] != "("
          return false # possessive: a++, a*+, a?+
        elsif char == "}" && pattern[i + 1] == "+" && pattern[0, i].match?(/\{\d*(,\d*)?\z/)
          return false # possessive: a{2,}+
        elsif char == ")"
          return false if open.empty?

          ambiguous = open.pop
          following = pattern[i + 1]
          return false if ambiguous && ["*", "+", "{"].include?(following)

          open[-1] = true if ambiguous && !open.empty?
        elsif !open.empty? && "|*+?{".include?(char)
          open[-1] = true
        end
        i += 1
      end
      open.empty? && free_repeats(pattern) <= 1
    end

    def literal_at(pattern, i)
      return nil if i >= pattern.size

      char = pattern[i]
      if char == "\\"
        following = pattern[i + 1]
        return following && !following.match?(/[a-z0-9]/i) ? following : nil
      end
      ".[](){}*+?|^$".include?(char) ? nil : char
    end

    # Two repeats that can both take the same text multiply each other's work
    # (".*=.*=.*x"). A repeat is pinned when the character straight after it is
    # one it can't match ("[^/]+/"); any other is free, and a pattern may hold
    # one free repeat.
    def free_repeats(pattern)
      free = 0
      i = 0
      n = pattern.size
      while i < n
        start = i
        char = pattern[i]
        if char == "\\"
          i += 2
        elsif char == "["
          i += 1
          i += pattern[i] == "\\" ? 2 : 1 while i < n && pattern[i] != "]"
          i += 1
        elsif char == "("
          i += pattern[i + 1] == "?" ? 3 : 1
          next
        elsif "|^$".include?(char)
          i += 1
          next
        else
          i += 1
        end
        # A group's text can't be tried against one character.
        atom = char == ")" ? nil : pattern[start...i]
        quantifier = pattern[i]
        repeats = ["*", "+"].include?(quantifier)
        if quantifier == "{"
          bounds = /\A\{(\d*)(,(\d*))?\}/.match(pattern[i..])
          next unless bounds

          # "{3}" is one length, not a choice; "{2,}" and "{2,9}" are choices.
          repeats = !bounds[2].nil? && bounds[3] != bounds[1]
          i += bounds[0].size - 1
        elsif quantifier != "?" && !repeats
          next
        end
        i += 1
        i += 1 if pattern[i] == "?"
        next unless repeats

        following = literal_at(pattern, i)
        pinned = false
        if atom && following
          begin
            pinned = !Regexp.new("\\A(?:#{atom})\\z", Regexp::IGNORECASE).match?(following)
          rescue RegexpError
            # Not an atom on its own: free.
            pinned = false
          end
        end
        free += 1 unless pinned
      end
      free
    end

    # ^ and $ outside character classes as \A and \z: what they mean in
    # JavaScript and Python (without a multiline flag).
    def ruby_anchors(pattern)
      out = +""
      i = 0
      in_class = false
      while i < pattern.size
        char = pattern[i]
        if char == "\\"
          out << pattern[i, 2]
          i += 2
          next
        end
        if in_class
          in_class = false if char == "]"
          out << char
        elsif char == "["
          in_class = true
          out << char
          # A "]" straight after "[" or "[^" is a literal.
          if pattern[i + 1] == "^"
            out << "^"
            i += 1
          end
          if pattern[i + 1] == "]"
            out << "]"
            i += 1
          end
        elsif char == "^"
          out << "\\A"
        elsif char == "$"
          out << "\\z"
        else
          out << char
        end
        i += 1
      end
      out
    end

    # Ruby before 3.2 can't stop a match that runs long, so there a rule's
    # regex is left out (its other parts still match): failing open, said
    # once. Our shape check refuses what we know to be slow, but a timeout
    # is what makes that safe to rely on.
    @regex_allowed = Regexp.respond_to?(:timeout)
    @warned = false

    class << self
      attr_accessor :regex_allowed
    end

    def regex_skipped
      return if @warned

      @warned = true
      warn "[analytics-platform] request rules: Ruby #{RUBY_VERSION} can't time out a regex, so patterns are skipped (their other parts still match); Ruby 3.2+ matches them"
    end

    def compile_regex(pattern)
      source = ruby_anchors(pattern)
      # Ruby before 3.2 has no per-pattern timeout (and reads the keyword as
      # a third positional argument), so ask which Ruby this is.
      if Regexp.respond_to?(:timeout)
        Regexp.new(source, Regexp::IGNORECASE, timeout: REGEX_TIMEOUT)
      else
        Regexp.new(source, Regexp::IGNORECASE)
      end
    end

    def section(data)
      return nil unless data.is_a?(Hash)

      out = {}
      MATCHERS.each do |matcher|
        entries = data[matcher]
        next unless entries.is_a?(Array)

        values = entries.select { |e| e.is_a?(String) && (matcher == "exact" || !e.empty?) }.map(&:downcase)
        out[matcher] = values unless values.empty?
      end
      pattern = data["regex"]
      if pattern && !RequestRules.regex_allowed
        regex_skipped
      elsif safe_pattern?(pattern)
        begin
          out["regex"] = compile_regex(pattern)
          # Anchored to the part's start or end: searched only in the window
          # that has it, never at a window's edge in the middle of the part.
          out["anchors"] = [pattern.start_with?("^"), ends_anchored?(pattern)]
        rescue RegexpError
          # A pattern we can't compile is dropped; the rule's other parts stay.
          nil
        end
      end
      out.empty? ? nil : out
    end

    # A "$" at the end that isn't escaped: "\$" is a dollar sign, "\\$" a
    # backslash and then the end.
    def ends_anchored?(pattern)
      pattern.end_with?("$") && pattern[0...-1][/\\*\z/].size.even?
    end

    # The rules as they will be matched; [] when there are none.
    def compile(data)
      given = data.is_a?(Hash) ? data["rules"] : nil
      rules = []
      (given.is_a?(Array) ? given : []).first(MAX_RULES).each do |rule|
        next unless rule.is_a?(Hash) && rule["id"].is_a?(String) && !rule["id"].empty?
        # We are called before the body is read, so a rule that needs the body
        # is skipped whole rather than matched on the rest of it.
        next if rule.key?("body")

        methods = rule["methods"]
        ban = rule["ban"]
        compiled = {
          "id" => rule["id"],
          "action" => rule["action"] == "block" ? "block" : "monitor",
          "ban" => ban.is_a?(Numeric) && ban.to_i.positive? ? ban.to_i : 0,
          "methods" => methods.is_a?(Array) ? methods.select { |m| m.is_a?(String) }.map(&:upcase) : []
        }
        count = 0
        SECTIONS.each do |name|
          part = section(rule[name])
          next unless part

          compiled[name] = part
          count += 1
        end
        # A rule with nothing to match would match everything.
        next if count.zero?

        rules << compiled
      end
      rules
    end

    # One pass only, as the protocol says: enough for %2e%2e, and no risk of
    # decoding a visitor's own text into something that looks like an attack.
    # An escape that isn't one stays as it is, and bytes that aren't UTF-8
    # become U+FFFD, as Python's unquote_plus does.
    def decode_once(text)
      return text unless text.include?("%") || text.include?("+")

      decoded = text.b.tr("+", " ").gsub(/%[0-9a-fA-F]{2}/n) { |m| m[1, 2].to_i(16).chr }
      decoded.force_encoding(Encoding::UTF_8).scrub("�")
    end

    def normalize_path(path)
      path.downcase.tr("\\", "/").gsub(%r{/{2,}}, "/")
    end

    # The path as a router reads it: ";params" dropped from each segment
    # (Tomcat, Jetty and some proxies do; "/x;y/../admin" is "/admin" to
    # them), decoded once, "\\" as "/", "//" as "/", "." and ".." resolved
    # (never above the root), lower-cased. The same as every package's.
    def router_path(path)
      text = normalize_path(decode_once(path.to_s.gsub(%r{;[^/]*}, "")))
      parts = []
      segments = text.split("/", -1)
      segments.each_with_index do |segment, index|
        if segment == ".."
          parts.pop if parts.size > 1
        elsif segment != "." && (!segment.empty? || index.zero?)
          parts << segment
        end
      end
      resolved = parts.join("/")
      resolved += "/" if ["", ".", ".."].include?(segments[-1]) && segments.size > 1 && !resolved.end_with?("/")
      resolved = "/#{resolved}" if text.start_with?("/") && !resolved.start_with?("/")
      resolved
    end

    # A request target's path (no query string) as the router reads it:
    # what the probes, the static-file check and the rules' path match too.
    # Resolved from the whole path, never a cut one: "/./././.../login" is
    # "/login" to a router however many "./" it carries.
    def normalize_target(target)
      router_path(SiteGoose.text(target).split(/[?#]/, 2)[0].to_s)
    end

    # Where a regex is searched in a part this long: the whole part when it
    # fits in one window, else windows starting 0, 1000, 2000, ... until one
    # reaches the end. first / last: the pattern is anchored to the part's
    # start / end, so only the window holding it counts.
    def window_starts(size, first, last)
      return [0] if size <= MAX_TEXT
      return [] if first && last

      final = (size - MAX_TEXT + WINDOW_STEP - 1) / WINDOW_STEP * WINDOW_STEP
      return [0] if first
      return [final] if last

      0.step(final, WINDOW_STEP)
    end

    # One timeout ends the search of the part: the next window would cost as much.
    def regex_hit?(part, text)
      regex = part["regex"]
      first, last = part["anchors"]
      window_starts(text.size, first, last).any? { |start| regex.match?(text[start, MAX_TEXT]) }
    rescue Regexp::TimeoutError
      false
    end

    def hits?(part, texts)
      texts.any? do |text|
        next true if part["exact"]&.include?(text)
        next true if part["prefix"]&.any? { |entry| text.start_with?(entry) }
        next true if part["suffix"]&.any? { |entry| !entry.empty? && text.end_with?(entry) }
        next true if part["contains"]&.any? { |entry| !entry.empty? && text.include?(entry) }

        part["regex"] ? regex_hit?(part, text) : false
      end
    end

    # The methods a rule's method list is compared with: the request's own;
    # for a POST, the method it asks to be routed as (Rack::MethodOverride,
    # which runs after us, turns a POST with X-HTTP-Method-Override: DELETE
    # or _method=patch into that); and GET for HEAD, which runs GET routes.
    def methods_of(method, overrides = nil)
      given = method.to_s.upcase
      methods = [given]
      if given == "POST"
        Array(overrides).each do |name|
          name = SiteGoose.text(name).strip.upcase
          methods << name if name.match?(METHOD_TOKEN)
        end
      end
      methods << "GET" if methods.include?("HEAD")
      methods.uniq
    end

    # The request's parts, prepared once for every rule and page limit:
    # method upper-cased, path raw/decoded/routed, query raw/decoded, ua.
    # target is the request target as the server received it, query string
    # and all. overrides: the method names a POST asks to be routed as.
    # also_path: the path the app routes on (Rack's SCRIPT_NAME + PATH_INFO)
    # when the server read the target differently; a hit on either counts.
    def prepare(method = "", target = "", user_agent = "", overrides: nil, also_path: nil)
      target = SiteGoose.text(target)
      # The path ends at the first "?" or "#", the query at a "#": a router
      # drops the fragment, so "/login#1" is the login.
      mark = target.index(/[?#]/)
      path_part = mark ? target[0, mark] : target
      query = mark && target[mark] == "?" ? target[(mark + 1)..].split("#", 2)[0].to_s : ""
      paths = [path_part]
      paths << SiteGoose.text(also_path) if also_path && !also_path.to_s.empty? && also_path != path_part
      # Lower-cased after decoding: %55NION decodes to "UNION", which a
      # lower-cased "union select" rule would otherwise never see.
      queries = [query.downcase, decode_once(query).downcase]
      {
        method: method.to_s.upcase,
        methods: methods_of(method, overrides),
        # Raw, decoded once and as the router reads it: "/x;y/../admin" is
        # "/admin" there, so a rule on "/admin" catches it; a hit on any counts.
        path_texts: paths.flat_map { |p| [normalize_path(p), normalize_path(decode_once(p)), router_path(p)] }.uniq,
        routed_path: router_path(path_part),
        query_texts: queries.uniq,
        ua: SiteGoose.text(user_agent).downcase
      }
    end

    # True when every section the rule names matches the prepared request.
    def matches?(rule, req)
      return false if !rule["methods"].empty? && (rule["methods"] & req[:methods]).empty?
      return false if rule["path"] && !hits?(rule["path"], req[:path_texts])
      return false if rule["query"] && !hits?(rule["query"], req[:query_texts])
      return false if rule["ua"] && !hits?(rule["ua"], [req[:ua]])

      true
    end

    # The first rule that matches, or nil. target is the request target as
    # the server received it, query string and all; prepared, when given, is
    # prepare() of the same request.
    def match(rules, method = "", target = "", user_agent = "", prepared = nil)
      return nil if rules.nil? || rules.empty?

      req = prepared || prepare(method, target, user_agent)
      rules.find { |rule| matches?(rule, req) }
    end
  end
end
