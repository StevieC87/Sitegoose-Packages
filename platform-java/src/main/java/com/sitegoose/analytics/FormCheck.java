package com.sitegoose.analytics;

import java.util.List;

/** What form protection made of a form. */
public final class FormCheck {
    /** Accept the form (false only when it is spam). */
    public final boolean ok;
    public final boolean spam;
    public final List<String> reasons;
    /** False when it couldn't be checked (the module off, the collector unreachable): the form is accepted. */
    public final boolean checked;

    FormCheck(boolean ok, boolean spam, List<String> reasons, boolean checked) {
        this.ok = ok;
        this.spam = spam;
        this.reasons = reasons;
        this.checked = checked;
    }

    @Override
    public String toString() {
        return "FormCheck{ok=" + ok + ", spam=" + spam + ", reasons=" + reasons + ", checked=" + checked + "}";
    }
}
