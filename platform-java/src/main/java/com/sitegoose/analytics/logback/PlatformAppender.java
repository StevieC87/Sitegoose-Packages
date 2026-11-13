package com.sitegoose.analytics.logback;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.AppenderBase;
import com.sitegoose.analytics.Platform;
import org.slf4j.LoggerFactory;

/**
 * Sends the exception of a Logback event at ERROR
 * ({@code log.error("...", error)}) as a "logged" error. An event without an
 * exception isn't sent: it has no stack to group it by. The Spring Boot
 * starter attaches it with analytics.errors.capture-logging=true; elsewhere:
 * {@code PlatformAppender.attach(platform)}, or in logback.xml (then call
 * {@link #setPlatform}).
 */
public final class PlatformAppender extends AppenderBase<ILoggingEvent> {
    public static final String NAME = "ANALYTICS_PLATFORM";
    private volatile Platform platform;

    public PlatformAppender() {
        setName(NAME);
    }

    public PlatformAppender(Platform platform) {
        this();
        this.platform = platform;
    }

    public void setPlatform(Platform platform) {
        this.platform = platform;
    }

    /** Started and on the root logger; null when Logback isn't the SLF4J backend. */
    public static PlatformAppender attach(Platform platform) {
        Object factory = LoggerFactory.getILoggerFactory();
        if (!(factory instanceof LoggerContext)) {
            return null;
        }
        LoggerContext context = (LoggerContext) factory;
        PlatformAppender appender = new PlatformAppender(platform);
        appender.setContext(context);
        appender.start();
        Logger root = context.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        root.detachAppender(NAME);
        root.addAppender(appender);
        return appender;
    }

    public void detach() {
        if (getContext() instanceof LoggerContext) {
            ((LoggerContext) getContext()).getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME).detachAppender(this);
        }
        stop();
    }

    @Override
    protected void append(ILoggingEvent event) {
        Platform target = platform;
        if (target == null || event == null || !event.getLevel().isGreaterOrEqual(Level.ERROR)) {
            return;
        }
        String name = event.getLoggerName();
        if (name != null && name.startsWith("com.sitegoose.analytics")) {
            return;
        }
        IThrowableProxy proxy = event.getThrowableProxy();
        if (!(proxy instanceof ThrowableProxy)) {
            return;
        }
        Throwable error = ((ThrowableProxy) proxy).getThrowable();
        if (error == null) {
            return;
        }
        try {
            target.captureException(Platform.unwrap(error), null, 0, "logged");
        } catch (RuntimeException ignored) {
            // never in the way of logging
        }
    }
}
