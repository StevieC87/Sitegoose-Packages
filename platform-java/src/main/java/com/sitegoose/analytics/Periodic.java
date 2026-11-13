package com.sitegoose.analytics;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.DoubleSupplier;

/**
 * Runs a job on the package's background threads; the job returns the
 * seconds until its next run. Never two runs of one job at once, and a job
 * that throws runs again a minute later: it never dies.
 */
final class Periodic {
    static final double RETRY = 60;

    private final ScheduledExecutorService pool;
    private final DoubleSupplier job;
    private ScheduledFuture<?> next;
    private boolean running;
    private boolean again;
    private boolean stopped;
    private Thread runner;

    Periodic(ScheduledExecutorService pool, DoubleSupplier job, double first) {
        this.pool = pool;
        this.job = job;
        synchronized (this) {
            schedule(first);
        }
    }

    private void schedule(double seconds) {
        if (stopped) {
            return;
        }
        try {
            next = pool.schedule(this::run, Math.max(0, (long) (seconds * 1000)), TimeUnit.MILLISECONDS);
        } catch (RuntimeException shutDown) {
            stopped = true;
        }
    }

    private void run() {
        synchronized (this) {
            if (stopped) {
                return;
            }
            if (running) {
                again = true;
                return;
            }
            running = true;
            runner = Thread.currentThread();
        }
        double wait;
        try {
            wait = job.getAsDouble();
        } catch (Throwable error) {
            // never let a job die
            wait = RETRY;
        }
        synchronized (this) {
            running = false;
            runner = null;
            if (again) {
                again = false;
                wait = 0;
            }
            schedule(wait);
            notifyAll();
        }
    }

    /** Runs the job as soon as a thread is free (once, if it is running now: again after it). */
    synchronized void runNow() {
        if (stopped) {
            return;
        }
        if (running) {
            again = true;
            return;
        }
        if (next != null) {
            next.cancel(false);
        }
        schedule(0);
    }

    /** Stops the job and waits (up to waitMs) for a run in progress to end. */
    synchronized void stop(long waitMs) {
        stopped = true;
        if (next != null) {
            next.cancel(false);
        }
        long until = System.currentTimeMillis() + waitMs;
        while (running && runner != Thread.currentThread()) {
            long left = until - System.currentTimeMillis();
            if (left <= 0) {
                break;
            }
            try {
                wait(left);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
}
