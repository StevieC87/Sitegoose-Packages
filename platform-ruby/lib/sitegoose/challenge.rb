# frozen_string_literal: true

# The browser check (rule `challenge`, sdk/protocols/firewall.md under "Flood
# protection"): a GET or HEAD that asks for a page, from an address with no
# valid pass, gets a small page instead of the site. Its script sets the pass
# cookie and reloads, which a script that doesn't run JavaScript never does.
#
# The pass is <day>.<first 32 hex digits of HMAC-SHA256(key, "<day>|<who>")>,
# key = HMAC-SHA256 of "sg-challenge-v1" keyed with the site secret, so any of
# the site's servers accepts a pass another one handed out. It counts for its
# own day and the next. sdk/protocols/challenge-cases.json holds the cases
# every client runs; backend/scripts/challenge-cases.mjs is the reference.

require "openssl"
require "securerandom"
require "ipaddr"
require "json"

module SiteGoose
  module Challenge
    COOKIE = "__sg_pass"
    MAX_AGE = 86_400
    LABEL = "sg-challenge-v1"
    PASS = /\A(\d{1,10})\.([0-9a-f]{32})\z/.freeze

    module_function

    # The key every pass is signed with, from the site secret.
    def pass_key(secret)
      OpenSSL::HMAC.digest("SHA256", secret.to_s, LABEL)
    end

    # What a pass is bound to: the IPv4 address (an IPv4-mapped IPv6 address
    # as IPv4), or an IPv6 address's /64 as four groups of four lower-case hex
    # digits. "*" for the agent's nginx (a package never accepts it); nil for
    # anything that isn't an address.
    def who(ip)
      text = ip.to_s.strip
      return "*" if text == "*"

      key = IP.key(text)
      return nil if key.nil?

      if key >> 32 == 0xFFFF
        v4 = key & 0xFFFFFFFF
        return [24, 16, 8, 0].map { |shift| (v4 >> shift) & 0xFF }.join(".")
      end
      format("%032x", key).scan(/.{4}/).first(4).join(":")
    end

    # Whole days since 1970-01-01 UTC.
    def day_of(now = nil)
      ((now || Time.now.to_f).to_f / 86_400).floor
    end

    def sign(key, day, bound)
      OpenSSL::HMAC.hexdigest("SHA256", key, "#{day}|#{bound}")[0, 32]
    end

    # Today's pass for this address, or "" when it isn't one.
    def make_pass(key, ip, now = nil)
      bound = who(ip)
      return "" if bound.nil?

      day = day_of(now)
      "#{day}.#{sign(key, day, bound)}"
    end

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      if OpenSSL.respond_to?(:fixed_length_secure_compare)
        OpenSSL.fixed_length_secure_compare(a, b)
      else
        diff = 0
        a.bytes.zip(b.bytes) { |x, y| diff |= x ^ y }
        diff.zero?
      end
    end

    # True when value is this address's pass for today or yesterday.
    def valid?(key, ip, value, now = nil)
      match = PASS.match(value.to_s)
      bound = who(ip)
      return false if match.nil? || bound.nil? || bound == "*"

      day = match[1].to_i
      today = day_of(now)
      return false unless day == today || day == today - 1

      secure_compare(match[2], sign(key, day, bound))
    end

    # Every value the Cookie header carries under name (a browser can send
    # two, from different paths); at most four, like the Node client. Two
    # Cookie headers arrive joined by ", " (Puma), so that separates cookies
    # too: our values ("<day>.<hex>", the preview code) never hold one, and a
    # piece of someone else's value split off this way names no cookie of ours.
    def cookie_values(cookie_header, name = COOKIE)
      found = []
      cookie_header.to_s.split(/;|, /).each do |part|
        k, sep, value = part.strip.partition("=")
        next if sep.empty? || k.strip != name

        found << value.strip.delete_prefix('"').delete_suffix('"')
        break if found.size == 4
      end
      found
    end

    def pass?(key, ip, cookie_header, now = nil)
      cookie_values(cookie_header).any? { |value| valid?(key, ip, value, now) }
    end

    # The rules' skip prefixes, lower-cased.
    def compile_skip(entries)
      Array(entries).select { |p| p.is_a?(String) && !p.empty? }.map(&:downcase).first(200)
    end

    # Conditions 1 to 3: a GET or HEAD, whose Accept asks for text/html, for a
    # path (lower-cased, no query string) under none of skip.
    def asks_for_page?(method, target, accept, skip)
      return false unless %w[GET HEAD].include?(method.to_s.upcase)
      return false unless accept.to_s.downcase.include?("text/html")

      path = target.to_s.split("?", 2)[0].to_s.split("#", 2)[0].to_s.downcase
      skip.none? { |prefix| path.start_with?(prefix) }
    end

    PAGE = <<~HTML
      <!doctype html>
      <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <meta name="robots" content="noindex"><title>Just a moment</title>
      <style nonce="%<nonce>s">body{font:16px/1.5 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#222;background:#fafafa}main{max-width:28rem;padding:2rem;text-align:center}</style>
      </head><body><main><p id="m">Checking your browser before you continue&hellip;</p>
      <noscript><p>Please turn on JavaScript to continue to this site.</p></noscript></main>
      <script nonce="%<nonce>s">%<script>s</script>
      </body></html>
    HTML

    # The page's script: sets the pass and reloads, but only when reading the
    # cookie back shows it was set (with cookies off it says so instead of
    # reloading forever), and at most three times a minute, counted in
    # sessionStorage (an address that changes on every request would otherwise
    # never get a pass that holds and reload for ever), or in a __sg_tries
    # cookie lasting a minute where storage is blocked or full. Secure only
    # when the browser is on https: it knows, where the server behind a proxy
    # can only be told. The same script as the Node, PHP and Python clients'.
    def script(value)
      "(function(){var n=#{COOKIE.to_json},v=#{value.to_json},m=document.getElementById(\"m\")," \
        "s=location.protocol===\"https:\";" \
        "document.cookie=n+\"=\"+v+\"; Max-Age=#{MAX_AGE}; Path=/; SameSite=Lax\"+(s?\"; Secure\":\"\");" \
        "if((\" \"+document.cookie+\";\").indexOf(\" \"+n+\"=\"+v+\";\")<0){m.textContent=\"Please allow cookies for this site, then reload the page.\";return;}" \
        "var k=\"__sg_tries\",r=0,t;" \
        "try{t=JSON.parse(sessionStorage.getItem(k)||\"[]\").filter(function(x){return Date.now()-x<60000;});r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}" \
        "catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+\"=\"+(r+1)+\"; Max-Age=60; Path=/; SameSite=Lax\"+(s?\"; Secure\":\"\");}" \
        "if(r>=3){m.textContent=\"This page couldn't be opened because your connection's address keeps changing. Please try again in a minute.\";return;}" \
        "location.reload();})();"
    end

    # [503, headers, body] for the check page: its own Content-Security-Policy
    # with a fresh nonce for its one script, and no body for a HEAD.
    def page(key, ip, method, now = nil)
      nonce = SecureRandom.urlsafe_base64(18)
      headers = {
        "content-type" => "text/html; charset=utf-8",
        "cache-control" => "no-store",
        "x-robots-tag" => "noindex",
        "content-security-policy" => "default-src 'none'; script-src 'nonce-#{nonce}'; style-src 'nonce-#{nonce}'; " \
                                     "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
      }
      return [503, headers, ""] if method.to_s.upcase == "HEAD"

      [503, headers, format(PAGE, nonce: nonce, script: script(make_pass(key, ip, now)))]
    end
  end
end
