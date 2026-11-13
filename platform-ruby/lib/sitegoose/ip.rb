# frozen_string_literal: true

require "ipaddr"

module SiteGoose
  # Addresses as integers in IPv6 space, IPv4 kept as ::ffff:a.b.c.d, so one
  # sorted list holds both (sdk/protocols/firewall.md: treat IPv4-mapped IPv6
  # as IPv4).
  module IP
    MAPPED = 0xFFFF << 32
    V4 = /\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/.freeze

    module_function

    # An address as an Integer in IPv6 space, or nil when it isn't one.
    def key(text)
      s = text.to_s.strip
      s = s.split("%", 2)[0] if s.include?("%")
      return nil if s.empty? || s.include?("/")

      if (m = V4.match(s))
        octets = m.captures
        return nil if octets.any? { |o| (o.size > 1 && o.start_with?("0")) || o.to_i > 255 }

        return MAPPED | octets.reduce(0) { |acc, o| (acc << 8) | o.to_i }
      end
      return nil unless s.include?(":")

      IPAddr.new(s).to_i
    rescue IPAddr::Error, ArgumentError
      nil
    end

    # "1.2.3.0/24" -> [start, end] as key()s, or nil. nil too for an IPv6
    # range that holds all of ::ffff:0:0/96 (::/64, ::/0): with IPv4 kept as
    # ::ffff:a.b.c.d it would match every IPv4 visitor, a /64 that is one
    # machine in IPv6 being the whole IPv4 internet here.
    def range(entry)
      s = entry.to_s.strip
      return nil if s.empty?

      address, bits = s.split("/", 2)
      net = IPAddr.new(address.to_s.split("%", 2)[0])
      if bits
        return nil unless bits.match?(/\A\d{1,3}\z/)

        prefix = bits.to_i
        return nil if prefix > (net.ipv4? ? 32 : 128)

        net = net.mask(prefix)
      end
      span = net.to_range
      first = span.first.to_i
      last = span.last.to_i
      return [MAPPED | first, MAPPED | last] if net.ipv4?
      return nil if first <= MAPPED && last >= (MAPPED | 0xFFFFFFFF)

      [first, last]
    rescue IPAddr::Error, ArgumentError
      nil
    end
  end

  # Addresses and ranges, merged and sorted, looked up by binary search.
  class IpSet
    def initialize(entries = [])
      ranges = Array(entries).filter_map { |e| e.is_a?(String) ? IP.range(e) : nil }.sort
      @starts = []
      @ends = []
      ranges.each do |first, last|
        if !@ends.empty? && first <= @ends[-1] + 1
          @ends[-1] = last if last > @ends[-1]
        else
          @starts << first
          @ends << last
        end
      end
    end

    def has?(key)
      return false if key.nil? || @starts.empty?

      after = @starts.bsearch_index { |start| start > key } || @starts.size
      i = after - 1
      i >= 0 && @ends[i] >= key
    end
    alias include? has?

    def size
      @starts.size
    end
  end

  # Cloudflare's published ranges (cloudflare.com/ips), the same list as
  # sdk/protocols/cloudflare-ranges.json (test/firewall_test.rb compares them):
  # CF-Connecting-IP is believed only from these, since anyone who reaches the
  # origin directly can send it.
  CLOUDFLARE = %w[
    173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18
    108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17
    162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
    2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32
    2a06:98c0::/29 2c0f:f248::/32
  ].freeze

  def self.from_cloudflare?(ip)
    key = IP.key(ip)
    return false if key.nil?

    @cloudflare ||= IpSet.new(CLOUDFLARE)
    @cloudflare.has?(key)
  end

  # The visitor's address. trust_proxy: nil/0 the connection's address; a
  # number of proxies in X-Forwarded-For (true = 1); "cloudflare" reads
  # CF-Connecting-IP, believed only when the connection comes from one of
  # Cloudflare's addresses; a callable gets the headers and returns it.
  #
  # A hop that isn't an address (a name, "unknown", garbage a client sent)
  # gives the connection's address instead, so the firewall still checks
  # the request; a port on a hop ("1.2.3.4:5678", "[2001:db8::1]:443", as
  # Azure's load balancer sends) is dropped.
  def self.client_ip(remote, headers, trust_proxy)
    remote = remote.to_s
    if trust_proxy.respond_to?(:call)
      given = hop(trust_proxy.call(headers))
      return IP.key(given) ? given : remote
    end

    if trust_proxy.to_s == "cloudflare"
      forwarded = hop(header(headers, "cf-connecting-ip"))
      return from_cloudflare?(remote) && IP.key(forwarded) ? forwarded : remote
    end
    hops = if trust_proxy == true then 1
           elsif trust_proxy.is_a?(Integer) then trust_proxy
           elsif trust_proxy.is_a?(String) && trust_proxy.match?(/\A\d+\z/) then trust_proxy.to_i
           else 0
           end
    if hops.positive?
      chain = header(headers, "x-forwarded-for").split(",").map(&:strip).reject(&:empty?)
      unless chain.empty?
        chosen = hop(chain[[0, chain.size - hops].max])
        return chosen if IP.key(chosen)
      end
    end
    remote
  end

  # One hop as an address: "[v6]:port" and "v4:port" lose the port.
  def self.hop(text)
    s = text.to_s.strip
    if s.start_with?("[")
      close = s.index("]")
      return close ? s[1...close] : s
    end
    found = /\A(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\z/.match(s)
    found ? found[1] : s
  end
end
