package com.sitegoose.analytics;

import com.mongodb.event.CommandFailedEvent;
import com.mongodb.event.CommandListener;
import com.mongodb.event.CommandStartedEvent;
import com.mongodb.event.CommandSucceededEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonValue;

/**
 * The MongoDB Java driver's queries, through its public command monitoring
 * (MongoClientSettings.Builder.addCommandListener): "find users {filter}"
 * with every value in the filter replaced by "?". Only loaded when the app
 * asks for it, so the driver stays the app's own, optional dependency.
 *
 * <p>The request is the one on the thread that started the command; the
 * reactive driver's commands start on its own threads, so they count as
 * background work.
 */
final class MongoListener implements CommandListener {
    /** Connection chatter, never recorded. */
    static final Set<String> CHATTER = new HashSet<>(Arrays.asList("hello", "isMaster", "ismaster", "ping", "buildInfo",
            "saslStart", "saslContinue", "getMore", "endSessions", "killCursors", "getLastError"));
    /** Commands started and not yet answered, at most this many (a driver that never answers can't fill memory). */
    static final int MAX_PENDING = 10000;
    private static final int DEPTH = 8;

    private static final class Started {
        final String statement;
        final RequestContext context;

        Started(String statement, RequestContext context) {
            this.statement = statement;
            this.context = context;
        }
    }

    private final Supplier<Queries> queries;
    private final Map<Integer, Started> pending = new ConcurrentHashMap<>();

    MongoListener(Supplier<Queries> queries) {
        this.queries = queries;
    }

    @Override
    public void commandStarted(CommandStartedEvent event) {
        try {
            Queries q = queries.get();
            if (q == null || !q.on() || CHATTER.contains(event.getCommandName())) {
                return;
            }
            if (pending.size() >= MAX_PENDING) {
                // Starts the driver never answered: let them go rather than stop counting.
                pending.clear();
            }
            String statement = statement(event.getCommandName(), event.getCommand());
            if (!statement.isEmpty()) {
                pending.put(event.getRequestId(), new Started(statement, RequestContext.current()));
            }
        } catch (RuntimeException ignored) {
            // timing never changes the command
        }
    }

    @Override
    public void commandSucceeded(CommandSucceededEvent event) {
        done(event.getRequestId(), event.getElapsedTime(TimeUnit.NANOSECONDS), false);
    }

    @Override
    public void commandFailed(CommandFailedEvent event) {
        done(event.getRequestId(), event.getElapsedTime(TimeUnit.NANOSECONDS), true);
    }

    private void done(int requestId, long nanos, boolean failed) {
        Started started = pending.remove(requestId);
        if (started == null) {
            return;
        }
        try {
            Queries q = queries.get();
            if (q != null && q.on()) {
                q.recordNormalized("mongodb", started.statement, nanos / 1e6, failed, started.context);
            }
        } catch (RuntimeException ignored) {
            // timing never changes the command
        }
    }

    /** "<command> <collection> <filter's shape>", normalized; "" when there's nothing to record. */
    static String statement(String command, BsonDocument document) {
        if (command == null || command.isEmpty()) {
            return "";
        }
        String collection = null;
        BsonValue named = document == null ? null : document.get(command);
        if (named != null && named.isString()) {
            collection = named.asString().getValue();
        }
        BsonValue filter = document == null ? null : filterOf(command, document);
        return QueryText.normalizeMongo(command, collection, filter == null ? null : plain(filter, 0), filter != null);
    }

    /** The filter (find), pipeline (aggregate), query (count, distinct, findAndModify) or first item's q (delete, update). */
    static BsonValue filterOf(String command, BsonDocument document) {
        switch (command) {
            case "find":
                return document.get("filter");
            case "aggregate":
                return document.get("pipeline");
            case "count":
            case "distinct":
            case "findAndModify":
                return document.get("query");
            case "delete":
            case "update": {
                BsonValue items = document.get("delete".equals(command) ? "deletes" : "updates");
                if (items != null && items.isArray() && !items.asArray().isEmpty()) {
                    BsonValue first = items.asArray().get(0);
                    return first.isDocument() ? first.asDocument().get("q") : null;
                }
                return null;
            }
            default:
                return null;
        }
    }

    /** A BSON value as the normalizer reads it: documents as maps (in order), arrays as lists, anything else a value. */
    static Object plain(BsonValue value, int depth) {
        if (depth > DEPTH) {
            return "?";
        }
        if (value.isDocument()) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, BsonValue> entry : value.asDocument().entrySet()) {
                out.put(entry.getKey(), plain(entry.getValue(), depth + 1));
            }
            return out;
        }
        if (value.isArray()) {
            BsonArray array = value.asArray();
            List<Object> out = new ArrayList<>(array.size());
            for (BsonValue item : array) {
                out.add(plain(item, depth + 1));
            }
            return out;
        }
        return "?";
    }
}
