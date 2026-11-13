package com.sitegoose.analytics;

import io.lettuce.core.event.command.CommandFailedEvent;
import io.lettuce.core.event.command.CommandListener;
import io.lettuce.core.event.command.CommandStartedEvent;
import io.lettuce.core.event.command.CommandSucceededEvent;
import io.lettuce.core.protocol.CommandArgs;
import io.lettuce.core.protocol.ProtocolKeyword;
import io.lettuce.core.protocol.RedisCommand;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Lettuce's Redis commands (what Spring Data Redis uses by default), through
 * its public command listener (RedisClient.addListener, Lettuce 6.1+): "GET
 * user:?" with the first key's shape and never an argument or a value
 * (sdk/protocols/queries.md, "Redis"). Only loaded when the app asks for it,
 * so Lettuce stays the app's own, optional dependency.
 *
 * <p>Lettuce shows a command's name and its first key (CommandArgs
 * getFirstEncodedKey), not its other arguments, so the command is put back
 * together from those two for QueryText.redisCommand: the key goes where
 * that command's first key goes. The second word of CLIENT, CONFIG, XINFO
 * and the like, and XREAD's BLOCK, come from CommandArgs.toCommandString(),
 * read for those commands only. A pipeline (auto-flush off) and MULTI/EXEC
 * reach the listener one command at a time, so each is recorded on its own.
 *
 * <p>The request is the one on the thread that wrote the command (the
 * caller's, for the sync and async APIs); the reactive API writes on
 * subscription, often a scheduler's thread, so those count as background.
 */
final class RedisListener implements CommandListener {
    /** Where a started command waits for its answer: the event's own context map, shared by its three events. */
    static final String STARTED = "com.sitegoose.analytics.started";
    private static final int NAMES_MAX = 1000;
    private static final Map<ProtocolKeyword, String> NAMES = new ConcurrentHashMap<>();

    private static final class Started {
        final String statement;
        final RequestContext context;
        final long nanos;

        Started(String statement, RequestContext context, long nanos) {
            this.statement = statement;
            this.context = context;
            this.nanos = nanos;
        }
    }

    private final Supplier<Queries> queries;

    RedisListener(Supplier<Queries> queries) {
        this.queries = queries;
    }

    @Override
    public void commandStarted(CommandStartedEvent event) {
        try {
            Queries q = queries.get();
            if (q == null || !q.on()) {
                return;
            }
            String statement = statement(event.getCommand());
            if (statement != null) {
                event.getContext().put(STARTED, new Started(statement, RequestContext.current(), System.nanoTime()));
            }
        } catch (RuntimeException ignored) {
            // timing never changes the command
        }
    }

    @Override
    public void commandSucceeded(CommandSucceededEvent event) {
        done(event.getContext(), false);
    }

    @Override
    public void commandFailed(CommandFailedEvent event) {
        done(event.getContext(), failed(event.getCause()));
    }

    private void done(Map<String, Object> context, boolean failed) {
        try {
            Object started = context == null ? null : context.remove(STARTED);
            if (!(started instanceof Started)) {
                return;
            }
            Started s = (Started) started;
            Queries q = queries.get();
            if (q != null && q.on()) {
                q.recordNormalized("redis", s.statement, (System.nanoTime() - s.nanos) / 1e6, failed, s.context);
            }
        } catch (RuntimeException ignored) {
            // timing never changes the command
        }
    }

    /** An error reply or no answer; a cluster's MOVED or ASK is a redirection, not an error. */
    static boolean failed(Throwable cause) {
        String message = cause == null ? null : cause.getMessage();
        return message == null || !(message.startsWith("MOVED ") || message.startsWith("ASK "));
    }

    /** The statement to record, or null when the command isn't timed. */
    static String statement(RedisCommand<?, ?, ?> command) {
        ProtocolKeyword type = command == null ? null : command.getType();
        if (type == null) {
            return null;
        }
        String name = nameOf(type);
        if (name == null) {
            return null;
        }
        String upper = QueryText.asciiUpper(name);
        if (QueryText.REDIS_WAITING.contains(upper)) {
            return null;
        }
        CommandArgs<?, ?> args = command.getArgs();
        String result = QueryText.redisCommand(argsOf(name, upper, args));
        return result == null ? null : QueryText.cut(result);
    }

    /** The command as redisCommand reads it, from its name, its first key and, for a few, its first words. */
    static List<Object> argsOf(String name, String upper, CommandArgs<?, ?> args) {
        if (QueryText.REDIS_NO_KEY.contains(upper)) {
            return Collections.singletonList(name);
        }
        if ("XREAD".equals(upper) || "XREADGROUP".equals(upper)) {
            return readArgsOf(name, "XREADGROUP".equals(upper), args);
        }
        if (QueryText.REDIS_CONTAINERS.contains(upper)) {
            String[] words = words(args);
            if (words.length == 0) {
                return Collections.singletonList(name);
            }
            String key = QueryText.REDIS_SUB_KEY.contains(upper) ? firstKey(args) : null;
            return key == null ? Arrays.asList(name, words[0]) : Arrays.asList(name, words[0], key);
        }
        String key = firstKey(args);
        if (key == null) {
            return Collections.singletonList(name);
        }
        if (QueryText.REDIS_SCRIPTS.contains(upper)) {
            return Arrays.asList(name, "", "1", key);
        }
        if (QueryText.REDIS_NUMKEYS.contains(upper)) {
            return Arrays.asList(name, "1", key);
        }
        if ("BITOP".equals(upper)) {
            return Arrays.asList(name, "", key);
        }
        return Arrays.asList(name, key);
    }

    /**
     * XREAD and XREADGROUP: XREADGROUP's GROUP, group and consumer first (the
     * two names written as Base64, so never a word), then the options up to
     * STREAMS, a BLOCK among them; a key after STREAMS may be called
     * anything, "block" too.
     */
    private static List<Object> readArgsOf(String name, boolean group, CommandArgs<?, ?> args) {
        List<Object> out = new ArrayList<>(6);
        out.add(name);
        if (group) {
            out.addAll(Arrays.asList("GROUP", "", ""));
        }
        String[] words = words(args);
        for (int i = group ? 3 : 0; i < words.length; i++) {
            String word = QueryText.asciiUpper(words[i]);
            if ("BLOCK".equals(word)) {
                out.add("BLOCK");
                return out;
            }
            if ("STREAMS".equals(word)) {
                break;
            }
        }
        String key = firstKey(args);
        if (key != null) {
            out.add("STREAMS");
            out.add(key);
        }
        return out;
    }

    /** The command's name as it goes on the wire (JSON.GET, not JSON_GET). */
    private static String nameOf(ProtocolKeyword type) {
        String name = NAMES.get(type);
        if (name == null) {
            byte[] bytes = type.getBytes();
            name = bytes == null ? type.name() : new String(bytes, StandardCharsets.UTF_8);
            if (name == null) {
                return null;
            }
            if (NAMES.size() < NAMES_MAX) {
                NAMES.put(type, name);
            }
        }
        return name;
    }

    /** The first key, decoded as UTF-8 (bytes that aren't become U+FFFD, then "?"), or null. */
    private static String firstKey(CommandArgs<?, ?> args) {
        if (args == null) {
            return null;
        }
        ByteBuffer key = args.getFirstEncodedKey();
        return key == null ? null : StandardCharsets.UTF_8.decode(key.duplicate()).toString();
    }

    /** The arguments as Lettuce writes them out, split on spaces: only for the few commands that need a word past the name. */
    private static String[] words(CommandArgs<?, ?> args) {
        if (args == null || args.count() == 0) {
            return new String[0];
        }
        String text = args.toCommandString();
        return text == null || text.isEmpty() ? new String[0] : text.split(" ");
    }
}
