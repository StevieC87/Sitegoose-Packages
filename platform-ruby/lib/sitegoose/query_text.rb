# frozen_string_literal: true

require "json"
require "strscan"

# Database queries with their values taken out (sdk/protocols/queries.md):
# the one rule every server package applies before a query leaves the
# customer's server. A port of expresscollect/Analytics/queryText.js, which
# is the reference; the tests run sdk/protocols/query-cases.json against it.
# Lengths are code points, and "whitespace" is what JavaScript's \s and
# trim() mean, so the two give the same text character for character.
#
#   SELECT * FROM users WHERE email = 'a@b.c' AND id IN (1, 2, 3)
#   -> SELECT * FROM users WHERE email = ? AND id IN (?)

module SiteGoose
  module QueryText
    MAX_STATEMENT = 1000
    OTHER_STATEMENT = "(other)"
    # The databases a row may name; anything else is "other".
    DATABASES = %w[postgresql mysql mariadb sqlite mssql oracle clickhouse mongodb redis other].freeze

    # JavaScript's \s (and what its trim() removes).
    SPACE = "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    TRIM = /\A[#{SPACE}]+|[#{SPACE}]+\z/.freeze
    NUMBER = /\A(?:0[xX][0-9a-fA-F]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)/.freeze
    DOLLAR_TAG_AT = /\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/.freeze
    PLACEHOLDER = "(?:\\?|\\$[0-9]+|:[A-Za-z0-9_]+|@[A-Za-z0-9_]+)"
    LIST = /\([#{SPACE}]*#{PLACEHOLDER}(?:[#{SPACE}]*,[#{SPACE}]*#{PLACEHOLDER})*[#{SPACE}]*\)/.freeze
    ROWS = /\(\?\)(?:[#{SPACE}]*,[#{SPACE}]*\(\?\))+/.freeze
    MONGO = /\A([^#{SPACE}]+)(?: ([^#{SPACE}]+))?(?: (.*))?\z/m.freeze
    # A JavaScript object lists keys that are array indexes first, in order.
    INDEX_KEY = /\A(?:0|[1-9][0-9]*)\z/.freeze
    # Where "..." may hold a value rather than a name: SQLite takes a
    # double-quoted string as a literal when no column has that name
    # (SQLCipher's PRAGMA key = "x'2DD2..'"), Oracle writes a password as a
    # quoted name, and an unknown database may do either. There "..." is
    # kept only when it reads as a plain name, closed: "email", never
    # "x'2D..'", "N3w P@ss" or an unclosed one.
    VALUE_QUOTES = %w[sqlite oracle other].freeze
    NAME = /\A"[A-Za-z_][A-Za-z0-9_$#]{0,127}"\z/.freeze

    # A keyword matched in either case, ASCII only, as JavaScript's /i reads
    # it: Ruby's /i would also take the Kelvin sign for a K.
    def self.either_case(word)
      word.gsub(/[A-Za-z]/) { |c| "[#{c.upcase}#{c.downcase}]" }
    end

    # A password or key written as a name, on any database: Oracle's
    # ALTER USER u IDENTIFIED BY pw and SQLCipher's PRAGMA key = "passphrase".
    # What follows is "?" whether it was a word or a quoted name. The
    # lookbehind is JavaScript's \b, ASCII only: Ruby's \b counts an accented
    # letter as a word character.
    SECRET_NAME = "(\"(?:[^\"]|\"\")*\"?|`(?:[^`]|``)*`?|[^#{SPACE};,()]+)"
    IDENTIFIED = /((?<![A-Za-z0-9_])#{either_case('IDENTIFIED BY ')})#{SECRET_NAME}/.freeze
    PRAGMA_KEY = /((?<![A-Za-z0-9_])#{either_case('PRAGMA ')}(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:#{either_case('HEX')})?(?:#{either_case('RE')})?#{either_case('KEY')} ?[=(] ?)#{SECRET_NAME}/.freeze

    module_function

    def trim(text)
      text.gsub(TRIM, "")
    end

    def database_of(db)
      name = db.nil? ? "" : SiteGoose.text(db).downcase
      DATABASES.include?(name) ? name : "other"
    end

    # The statement to store, or "" when nothing is left of it.
    def normalize_statement(text, db)
      return "" unless text.is_a?(String)

      text = SiteGoose.text(text)
      return text if text == OTHER_STATEMENT

      db = database_of(db)
      shaped = if db == "mongodb"
        mongo_statement(text)
      elsif db == "redis"
        redis_statement(text)
      elsif db == "other" && text.include?("\\")
        # A database we don't know may or may not take a backslash as an
        # escape, and each reading leaks what the other hides. When they
        # disagree the query keeps its timing under (other) and its text is
        # left out.
        escaped = sql_shape(text, db, false)
        escaped == sql_shape(text, db, true) ? escaped : OTHER_STATEMENT
      else
        sql_shape(text, db)
      end
      cut(shaped)
    end

    def cut(text)
      text.length > MAX_STATEMENT ? trim(text[0, MAX_STATEMENT]) : text
    end

    # The word characters: a digit right after one is part of a name or a
    # placeholder (table2, $1, @p1, :1), not a value. ASCII only, in every
    # package, so no byte of a multi-byte character is one.
    WORD_BYTE = Array.new(256, false).tap do |table|
      [*"A".."Z", *"a".."z", *"0".."9", "_", "$", "@", ":"].each { |c| table[c.ord] = true }
    end
    NAME_BYTE = Array.new(256, false).tap do |table|
      [*"A".."Z", *"a".."z", *"0".."9", "_"].each { |c| table[c.ord] = true }
    end
    PREFIX_BYTES = "EeNnXxBb".bytes.freeze
    QUOTE = 39 # '
    DOUBLE_QUOTE = 34 # "
    BACKTICK = 96 # `
    DOLLAR = 36 # $
    BACKSLASH = 92
    SPACE_BYTE = 32
    DIGIT_BYTE = Array.new(256, false).tap { |table| ("0".."9").each { |c| table[c.ord] = true } }
    NAME_START_BYTE = Array.new(256, false).tap do |table|
      [*"A".."Z", *"a".."z", "_", "@", ":"].each { |c| table[c.ord] = true }
    end
    DASH = 45
    HASH = 35
    SLASH = 47
    STAR = 42
    DOT = 46
    # The runs the scan copies or skips whole; each stops where a character
    # of another rule starts.
    TO_LINE_END = /[^\n]*/.freeze
    BLOCK_END = %r{\*/}.freeze
    SPACE_RUN = /[#{SPACE}]+/.freeze
    # A letter, _, @ or : is copied, and so is every word character after
    # one: a digit or $ that follows a word character is part of the name.
    NAME_RUN = /[A-Za-z_@:][A-Za-z0-9_$@:]*/.freeze
    NUMBER_AT = /(?:0[xX][0-9a-fA-F]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)/.freeze
    # A number is read from at most this many characters, as the reference does.
    NUMBER_MAX = 400
    TAG_MAX = 64
    QUOTE_STOPS = {}.tap do |stops|
      [QUOTE, DOUBLE_QUOTE, BACKTICK].each do |byte|
        quote = Regexp.escape(byte.chr)
        stops[[byte, true]] = /[#{quote}\\]/
        stops[[byte, false]] = /#{quote}/
      end
    end.freeze

    # Moves the scanner past a quoted run starting at the opening quote: past
    # the closing quote, or to the end. A doubled quote escapes, and a
    # backslash too unless backslash is false.
    def skip_quoted(scanner, quote, backslash)
      text = scanner.string
      stop = QUOTE_STOPS[[quote, backslash]]
      scanner.pos += 1
      loop do
        return scanner.terminate unless scanner.skip_until(stop)

        if text.getbyte(scanner.pos - 1) == BACKSLASH
          scanner.getch
        elsif text.getbyte(scanner.pos) == quote
          scanner.pos += 1
        else
          return
        end
      end
    end

    # The scan below reads runs with StringScanner rather than character by
    # character, one step per token: time grows with the text, never faster
    # (an 800 KB bulk insert of 27,000 rows takes about 0.4 s, 0.2 s with
    # YJIT). The rules are the table's, in its order; "the character
    # before" is always the input's.
    def sql_shape(sql, db, backslash_literal = nil)
      mysql = %w[mysql mariadb].include?(db)
      postgres = db == "postgresql"
      # Where a backslash in a string is just a character: PostgreSQL's plain
      # strings (standard_conforming_strings, on since 9.1), SQLite, SQL
      # Server and Oracle. Read as an escape there, 'C:\' ends late and lets
      # what follows out. MySQL, MariaDB, ClickHouse and unknown databases
      # escape.
      literal = backslash_literal.nil? ? (postgres || %w[sqlite mssql oracle].include?(db)) : backslash_literal
      scanner = StringScanner.new(sql)
      out = +""
      until scanner.eos?
        at = scanner.pos
        byte = sql.getbyte(at)
        word_before = at.positive? && WORD_BYTE[sql.getbyte(at - 1)]
        if (byte == DASH && sql.getbyte(at + 1) == DASH) || (byte == HASH && mysql)
          scanner.skip(TO_LINE_END)
          out << " " unless out.empty? || out.getbyte(-1) == SPACE_BYTE
        elsif byte == SLASH && sql.getbyte(at + 1) == STAR
          scanner.pos += 2
          scanner.terminate unless scanner.skip_until(BLOCK_END)
          out << " " unless out.empty? || out.getbyte(-1) == SPACE_BYTE
        elsif byte == QUOTE || (byte == DOUBLE_QUOTE && mysql)
          last = out.getbyte(-1)
          prefixed = PREFIX_BYTES.include?(last) && (out.bytesize == 1 || !NAME_BYTE[out.getbyte(-2)])
          # Only PostgreSQL's E'..' escapes with a backslash where it is literal.
          escapes = !literal || (postgres && prefixed && (last == 69 || last == 101))
          out.chop! if prefixed
          skip_quoted(scanner, byte, escapes)
          out << "?"
        elsif byte == DOUBLE_QUOTE || byte == BACKTICK
          skip_quoted(scanner, byte, !literal)
          run = sql.byteslice(at, scanner.pos - at)
          out << (byte == DOUBLE_QUOTE && VALUE_QUOTES.include?(db) && !run.match?(NAME) ? "?" : run)
        elsif byte == DOLLAR && !word_before && (tag = scanner.check(DOLLAR_TAG_AT)) && tag.size <= TAG_MAX
          scanner.pos += tag.bytesize
          scanner.terminate unless scanner.skip_until(/#{Regexp.escape(tag)}/)
          out << "?"
        elsif !word_before && (DIGIT_BYTE[byte] || (byte == DOT && DIGIT_BYTE[sql.getbyte(at + 1).to_i]))
          # Past NUMBER_MAX characters the number is read from those alone.
          length = scanner.skip(NUMBER_AT)
          scanner.pos = at + sql.byteslice(at, NUMBER_MAX).b[NUMBER].bytesize if length > NUMBER_MAX
          out << "?"
        elsif (byte <= SPACE_BYTE || byte >= 128) && scanner.skip(SPACE_RUN)
          out << " " unless out.empty? || out.getbyte(-1) == SPACE_BYTE
        elsif NAME_START_BYTE[byte]
          out << scanner.scan(NAME_RUN)
        else
          out << scanner.getch
        end
      end
      trim(out.gsub(IDENTIFIED, "\\1?").gsub(PRAGMA_KEY, "\\1?").gsub(LIST, "(?)").gsub(ROWS, "(?)"))
    end

    # A Mongo filter or pipeline's shape: keys kept, every value "?", and an
    # array whose items all have the same shape kept as one.
    def mongo_shape(value, depth = 0)
      return "?" if depth >= 6

      case value
      when Array
        items = value.map { |item| mongo_shape(item, depth + 1) }
        items.map { |item| JSON.generate(item) }.uniq.size == 1 ? [items[0]] : items
      when Hash
        # JavaScript's out[key] = ... sets the prototype for "__proto__",
        # which its JSON.stringify then leaves out.
        pairs = value.map { |key, item| [key.to_s, item] }.reject { |key, _| key == "__proto__" }
        index, named = pairs.partition { |key, _| key.match?(INDEX_KEY) && key.to_i < 4_294_967_295 }
        (index.sort_by { |key, _| key.to_i } + named).each_with_object({}) do |(key, item), out|
          out[key] = mongo_shape(item, depth + 1)
        end
      else "?"
      end
    end

    # Ruby's parser takes comments, raw control characters and unknown
    # escapes (\x) that JavaScript's JSON.parse refuses: text with any is
    # not JSON here.
    def strict_json?(text)
      quoted = false
      escaped = false
      hex = 0
      text.each_char do |c|
        if hex.positive?
          return false unless c.match?(/\h/)

          hex -= 1
        elsif quoted
          if escaped
            return false unless '"\\/bfnrtu'.include?(c)

            escaped = false
            hex = 4 if c == "u"
          elsif c == "\\" then escaped = true
          elsif c == '"' then quoted = false
          elsif c.ord < 0x20 then return false
          end
        elsif c == '"' then quoted = true
        elsif c == "/" then return false
        end
      end
      true
    end

    # JavaScript takes a lone surrogate (\ud800) and writes it back escaped;
    # Ruby refuses it. Each is read as a code point of U+100000..U+1007FF
    # instead and written back as JavaScript does: text that already has one
    # of those can't be told apart, and isn't JSON here.
    ESCAPE = /\\(?:u([dD][89abAB]\h\h\\u[dD][c-fC-F]\h\h)|u([dD][89a-fA-F]\h\h)|.)/m.freeze
    STAND_IN = 0x100000 - 0xD800
    STAND_INS = /[\u{100000}-\u{1007ff}]/.freeze

    def stand_in_surrogates(text)
      return text unless text.include?("\\u")

      out = text.gsub(ESCAPE) do
        lone = Regexp.last_match(2)
        lone ? (lone.hex + STAND_IN).chr(Encoding::UTF_8) : Regexp.last_match(0)
      end
      out == text || !text.match?(STAND_INS) ? out : nil
    end

    def written_surrogates(json)
      json.gsub(STAND_INS) { |c| format("\\u%04x", c.ord - STAND_IN) }
    end

    # ---- Redis: the command and its first key's shape (queries.md, "Redis") ----
    # A key keeps each ":" segment that is only letters and "_" (32 at most);
    # every other segment is "?", so IDs, slugs, emails and hashes never
    # leave the server: user:42:cart -> user:?:cart. ASCII only, read as
    # bytes, so a key that isn't UTF-8 is "?" rather than an error.
    REDIS_WORD = /\A[A-Za-z][A-Za-z0-9_.|-]{0,39}\z/n.freeze
    REDIS_SEGMENT = /\A[A-Za-z_]{1,32}\z/n.freeze
    # Commands whose second word is a subcommand (CLIENT SETNAME, XINFO STREAM).
    REDIS_CONTAINERS = %w[ACL CLIENT CLUSTER COMMAND CONFIG DEBUG FUNCTION LATENCY MEMORY MODULE OBJECT PUBSUB SCRIPT
                          SLOWLOG XGROUP XINFO].to_h { |name| [name, true] }.freeze
    # Of those, the ones with a key after the subcommand.
    REDIS_SUB_KEY = %w[OBJECT MEMORY XGROUP XINFO].to_h { |name| [name, true] }.freeze
    # No key: what follows is a password, a message, a number or nothing.
    REDIS_NO_KEY = %w[PING ECHO INFO AUTH HELLO SELECT QUIT RESET MULTI EXEC DISCARD UNWATCH DBSIZE TIME FLUSHDB
                      FLUSHALL SAVE BGSAVE BGREWRITEAOF LASTSAVE SCAN RANDOMKEY SWAPDB SHUTDOWN ROLE REPLICAOF SLAVEOF
                      READONLY READWRITE LOLWUT FAILOVER PSYNC SYNC REPLCONF MIGRATE].to_h { |name| [name, true] }.freeze
    # Script calls: script or name, then how many keys, then the keys.
    REDIS_SCRIPTS = %w[EVAL EVALSHA EVAL_RO EVALSHA_RO FCALL FCALL_RO].to_h { |name| [name, true] }.freeze
    # How many keys first, then the keys.
    REDIS_NUMKEYS = %w[ZUNION ZINTER ZDIFF SINTERCARD ZINTERCARD LMPOP ZMPOP].to_h { |name| [name, true] }.freeze
    # Waiting, not working: a queue worker sits in these for seconds, so
    # timing them would put every idle worker at the top of the slow list.
    REDIS_WAITING = %w[BLPOP BRPOP BRPOPLPUSH BLMOVE BLMPOP BZPOPMIN BZPOPMAX BZMPOP WAIT WAITAOF SUBSCRIBE PSUBSCRIBE
                       SSUBSCRIBE UNSUBSCRIBE PUNSUBSCRIBE SUNSUBSCRIBE MONITOR].to_h { |name| [name, true] }.freeze
    REDIS_PREFIXES = { "PIPELINE" => true, "MULTI" => true }.freeze
    REDIS_SPLIT = /[#{SPACE}]+/.freeze
    # JavaScript's Number() of a string, for "how many keys": decimal, or
    # 0x/0o/0b, or Infinity.
    JS_INFINITY = /\A[+-]?Infinity\z/.freeze
    JS_DECIMAL = /\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/.freeze
    JS_RADIX = /\A0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)\z/.freeze

    def redis_key_shape(key)
      # An empty key is "?" too: "GET " would read back as "GET".
      return "?" if !key.is_a?(String) || key.empty?

      # split drops trailing empty parts; -1 keeps them, as JavaScript does.
      key.b.split(":", -1).map { |part| part.empty? || part.match?(REDIS_SEGMENT) ? part : "?" }.join(":").force_encoding(Encoding::UTF_8)
    end

    # Number(value) > 0, as JavaScript reads it.
    def js_positive?(value)
      case value
      when Integer, Float then value.positive?
      when true then true
      when String
        text = trim(SiteGoose.text(value))
        if text.match?(JS_INFINITY) then !text.start_with?("-")
        elsif text.match?(JS_DECIMAL) then text.to_f.positive?
        # Integer() reads the same 0x/0o/0b prefixes.
        elsif text.match?(JS_RADIX) then Integer(text).positive?
        else false
        end
      else false
      end
    end

    # A Redis word as the rule reads it (upper case), or nil when it isn't one.
    def redis_word(value)
      value.is_a?(String) && value.b.match?(REDIS_WORD) ? value.b.upcase(:ascii).force_encoding(Encoding::UTF_8) : nil
    end

    # A command as the client sends it (["GET", "user:42"]) -> "GET user:?",
    # or nil for one that isn't timed (blocking, or not a command).
    def redis_command(args)
      return nil unless args.is_a?(Array)

      name = redis_word(args[0])
      return nil if name.nil? || REDIS_WAITING.key?(name)

      key = nil
      command = name
      if REDIS_CONTAINERS.key?(name)
        sub = redis_word(args[1])
        if sub
          command = "#{name} #{sub}"
          # Only after a subcommand: "OBJECT user" would read back as OBJECT USER.
          key = 2 if REDIS_SUB_KEY.key?(name)
        end
      elsif name == "XREAD" || name == "XREADGROUP"
        # Its options, then STREAMS and the keys. XREADGROUP's group and
        # consumer come first and may be named anything, as may a stream.
        ((name == "XREADGROUP" ? 4 : 1)...args.size).each do |i|
          arg = args[i]
          next unless arg.is_a?(String)

          word = arg.b.upcase(:ascii)
          return nil if word == "BLOCK"

          if word == "STREAMS"
            key = i + 1
            break
          end
        end
      elsif REDIS_SCRIPTS.key?(name)
        key = 3 if args.size > 2 && js_positive?(args[2])
      elsif REDIS_NUMKEYS.key?(name)
        key = 2 if args.size > 1 && js_positive?(args[1])
      elsif name == "BITOP"
        key = 2
      elsif !REDIS_NO_KEY.key?(name) && !REDIS_PREFIXES.key?(name)
        key = 1
      end
      key && key < args.size ? "#{command} #{redis_key_shape(args[key])}" : command
    end

    # A statement a package sent: [PIPELINE|MULTI] COMMAND [SUBCOMMAND] [key].
    # Anything else (an argument a hook let through) is (other).
    def redis_statement(text)
      words = trim(text).split(REDIS_SPLIT)
      return "" if words.empty?

      out = []
      i = 0
      if words.size > 1 && REDIS_PREFIXES.key?(words[0].upcase(:ascii))
        out << words[0].upcase(:ascii)
        i = 1
      end
      name = redis_word(words[i])
      return OTHER_STATEMENT if name.nil? || REDIS_WAITING.key?(name)

      i += 1
      out << name
      if REDIS_CONTAINERS.key?(name) && i < words.size && (sub = redis_word(words[i]))
        out << sub
        i += 1
      end
      return OTHER_STATEMENT if i < words.size - 1

      out << redis_key_shape(words[i]) if i < words.size
      out.join(" ")
    end

    # "find users {...}": the command, the collection, and the filter's shape.
    def mongo_statement(text)
      match = MONGO.match(trim(text))
      return "" unless match

      command, collection, rest = match.captures
      # A "collection" with a brace, bracket or quote in it is the filter's start.
      if collection&.match?(/[{}\[\]"']/)
        rest = rest.nil? ? collection : "#{collection} #{rest}"
        collection = nil
      end
      shape = ""
      json = rest && strict_json?(rest) ? stand_in_surrogates(rest) : nil
      if json
        begin
          shape = JSON.generate(mongo_shape(JSON.parse(json, max_nesting: false)))
          shape = written_surrogates(shape) unless json == rest
        rescue JSON::ParserError, JSON::GeneratorError, EncodingError, TypeError
          shape = ""
        end
      end
      [command, collection, shape].reject { |part| part.nil? || part.empty? }.join(" ")
    end
  end
end
