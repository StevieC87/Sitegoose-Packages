using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>What /events/lead answered: "created" or "updated", and the lead's ID.</summary>
public sealed class LeadResult
{
    public string Status { get; set; } = "";
    public string LeadId { get; set; } = "";
}

/// <summary>Analytics module: what only the server sees for sure (payments,
/// sign-ups, plan changes), next to the browser tracker's visits. Not
/// pageviews: the tracker counts those.
/// - Track(): events, batched to POST /events/server-events in the background.
///   Each gets an event_uid, so a retried batch can be told apart from new events.
/// - IdentifyAsync(): links the browser's visit to your user ID (/events/identify),
///   with optional traits about the user (plan, seats...).
/// - LeadAsync(): adds or updates a lead (/events/lead).
/// Pass sessionId to link an event to the visit: the page sends
/// window.analyticsSession.getId() in the X-Analytics-Session header, and
/// Platform.SessionId(HttpContext) reads it.</summary>
internal sealed class Analytics
{
    public const int Batch = 100;
    public const int QueueMax = 1000;
    public const int FlushEvery = 2;
    public const int Retry = 15;

    private readonly Core core;
    // Bounded: past QueueMax new events are dropped rather than queued without end.
    private readonly Channel<Dictionary<string, object?>> channel =
        Channel.CreateBounded<Dictionary<string, object?>>(new BoundedChannelOptions(QueueMax) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
    // A batch the collector couldn't take, sent first next time.
    private List<Dictionary<string, object?>> retry = new();
    private readonly SemaphoreSlim flushing = new(1, 1);
    private readonly Periodic? job;

    public Analytics(Core core)
    {
        this.core = core;
        if (core.Valid) job = core.Every(async () => await FlushAsync().ConfigureAwait(false) ? FlushEvery : Retry, FlushEvery);
    }

    internal int QueueCount => channel.Reader.Count + retry.Count;

    /// <summary>name: the event's name; fields: value, numeric_value, currency, url,
    /// event_label, variant, id, timestamp, event_uid, transaction_id, coupon
    /// (expresscollect/docs/server-events.md). Returns the event_uid, or "" when not queued.</summary>
    public string Track(string name, IDictionary<string, object?>? fields = null, string? sessionId = "")
    {
        if (string.IsNullOrEmpty(name) || !core.IsOn("analytics")) return "";
        var evt = new Dictionary<string, object?>
        {
            ["timestamp"] = J.Now(),
            ["session_id"] = sessionId ?? "",
        };
        if (fields != null)
        {
            foreach (var pair in fields) evt[pair.Key] = pair.Value;
        }
        evt["event_name"] = J.Clip(name, 100);
        var uid = fields != null && fields.TryGetValue("event_uid", out var given) && given is string s && s.Length > 0 ? s : Guid.NewGuid().ToString();
        evt["event_uid"] = uid;
        // Amounts as decimal strings, so they arrive exact.
        if (evt.TryGetValue("numeric_value", out var amount) && amount is not null and not string)
        {
            evt["numeric_value"] = Convert.ToString(amount, CultureInfo.InvariantCulture);
        }
        // Turned into JSON now, so a field that can't be (a stream, a cycle)
        // fails here, in your code's log, and never holds up the events after it.
        try
        {
            var element = J.Parse(J.Serialize(evt));
            if (element == null) return "";
            evt = element.Value.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value.Clone());
        }
        catch (Exception error)
        {
            core.Log("analytics", "event " + name + " dropped, its fields aren't JSON: " + error.Message);
            return "";
        }
        if (!channel.Writer.TryWrite(evt))
        {
            core.Log("analytics", "queue full, event dropped");
            return "";
        }
        if (channel.Reader.Count >= Batch) job?.RunNow();
        return uid;
    }

    /// <summary>Sends what's waiting; false when some of it must be tried again.</summary>
    public async Task<bool> FlushAsync()
    {
        await flushing.WaitAsync().ConfigureAwait(false);
        try
        {
            var waiting = retry;
            retry = new List<Dictionary<string, object?>>();
            while (channel.Reader.TryRead(out var evt)) waiting.Add(evt);
            var ok = true;
            for (var i = 0; i < waiting.Count; i += Batch)
            {
                var batch = waiting.Skip(i).Take(Batch).ToList();
                var res = await core.SendAsync("analytics", "/events/server-events", "POST", new Dictionary<string, object?> { ["events"] = batch }).ConfigureAwait(false);
                if (res == null || res.Status == 429 || res.Status >= 500)
                {
                    // The collector is away: this batch and the rest wait for the next try.
                    ok = false;
                    retry = waiting.Skip(i).Take(QueueMax).ToList();
                    break;
                }
                if (!res.Ok) core.Log("analytics", "events refused: " + res.Text());
            }
            return ok;
        }
        finally
        {
            flushing.Release();
        }
    }

    /// <summary>Links the visit to your user ID. True when stored. traits:
    /// what you know about the user, name to text, number or bool; anything
    /// else is left out, and the collector cleans the names and values.</summary>
    public async Task<bool> IdentifyAsync(string? userId, string? sessionId, IDictionary<string, object?>? traits = null)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(sessionId) || !core.IsOn("analytics")) return false;
        var body = new Dictionary<string, object?> { ["user_id"] = userId, ["session_id"] = sessionId };
        var kept = ScalarTraits(traits);
        if (kept.Count > 0) body["traits"] = kept;
        var res = await core.SendAsync("analytics", "/events/identify", "POST", body).ConfigureAwait(false);
        return res != null && res.Ok;
    }

    /// <summary>The traits that are text, a (finite) number or a bool.</summary>
    internal static Dictionary<string, object?> ScalarTraits(IDictionary<string, object?>? traits)
    {
        var kept = new Dictionary<string, object?>();
        if (traits == null) return kept;
        foreach (var pair in traits)
        {
            switch (pair.Value)
            {
                case string or bool or int or long or short or byte or sbyte or uint or ulong or ushort or decimal:
                    kept[pair.Key] = pair.Value;
                    break;
                case double d when double.IsFinite(d):
                    kept[pair.Key] = d;
                    break;
                case float f when float.IsFinite(f):
                    kept[pair.Key] = f;
                    break;
            }
        }
        return kept;
    }

    /// <summary>fields: email or phone, and name, status, tags, note, fields,
    /// source, consent, lost_reason, deal_value, currency. Null when not stored.</summary>
    public async Task<LeadResult?> LeadAsync(IDictionary<string, object?> fields, string? sessionId = "")
    {
        if (!core.IsOn("analytics")) return null;
        var body = new Dictionary<string, object?> { ["session_id"] = sessionId ?? "" };
        foreach (var pair in fields ?? new Dictionary<string, object?>()) body[pair.Key] = pair.Value;
        var res = await core.SendAsync("analytics", "/events/lead", "POST", body).ConfigureAwait(false);
        if (res == null) return null;
        if (!res.Ok)
        {
            core.Log("analytics", "lead refused: " + res.Text());
            return null;
        }
        var data = res.Json();
        return new LeadResult { Status = J.Str(J.Prop(data, "status")) ?? "", LeadId = J.Str(J.Prop(data, "lead_id")) ?? "" };
    }

    public Task CloseAsync() => FlushAsync();
}

/// <summary>Audit log module: who did what on your site, sent to POST
/// /events/audit in small batches in the background (Security -> Audit log).
/// What goes in (names, emails) is up to you. Cookie sign-ins and sign-outs
/// are recorded on their own.</summary>
internal sealed class Audit
{
    public const int Batch = 100;
    public const int QueueMax = 1000;
    public const int FlushEvery = 5;

    private readonly Core core;
    private readonly Channel<Dictionary<string, object?>> channel =
        Channel.CreateBounded<Dictionary<string, object?>>(new BoundedChannelOptions(QueueMax) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
    private readonly SemaphoreSlim flushing = new(1, 1);
    private readonly Periodic? job;

    public Audit(Core core)
    {
        this.core = core;
        if (core.Valid)
        {
            job = core.Every(async () =>
            {
                await FlushAsync().ConfigureAwait(false);
                return FlushEvery;
            }, FlushEvery);
        }
    }

    internal int QueueCount => channel.Reader.Count;

    public void Record(string? action, string? actor = "", string? target = "", object? details = null, string? actorIp = "", string? sessionId = "")
    {
        if (!core.IsOn("audit") || string.IsNullOrEmpty(action)) return;
        var entry = new Dictionary<string, object?>
        {
            ["at"] = J.Now(),
            ["action"] = J.Clip(action, 64),
            ["actor"] = J.Clip(actor ?? "", 200),
            ["target"] = J.Clip(target ?? "", 300),
            ["details"] = details,
            ["actor_ip"] = actorIp ?? "",
            ["session_id"] = sessionId ?? "",
        };
        if (!channel.Writer.TryWrite(entry)) return;
        if (channel.Reader.Count >= Batch) job?.RunNow();
    }

    public async Task FlushAsync()
    {
        await flushing.WaitAsync().ConfigureAwait(false);
        try
        {
            var waiting = new List<Dictionary<string, object?>>();
            while (channel.Reader.TryRead(out var entry)) waiting.Add(entry);
            for (var i = 0; i < waiting.Count; i += Batch)
            {
                await core.SendAsync("audit", "/events/audit", "POST",
                    new Dictionary<string, object?> { ["entries"] = waiting.Skip(i).Take(Batch).ToList() }).ConfigureAwait(false);
            }
        }
        finally
        {
            flushing.Release();
        }
    }

    public Task CloseAsync() => FlushAsync();
}

/// <summary>Feature flags module: turn features of your app on or off from the
/// dashboard, for everyone, a share of users, or listed user IDs. IsEnabled()
/// answers from memory; the flags come with the module switches.</summary>
internal sealed class Flags
{
    private readonly Core core;

    public Flags(Core core)
    {
        this.core = core;
    }

    /// <summary>FNV-1a over "key:user", 0-99: the same as the Node, PHP and Python packages.</summary>
    public static int Bucket(string key, string user)
    {
        uint h = 0x811C9DC5;
        foreach (var b in System.Text.Encoding.UTF8.GetBytes(key + ":" + user))
        {
            h ^= b;
            unchecked
            {
                h *= 0x01000193;
            }
        }
        return (int)(h % 100);
    }

    internal static bool? Evaluate(Flag flag, string key, string? user)
    {
        if (!flag.On) return false;
        var uid = user ?? "";
        if (uid.Length > 0 && flag.Users.Contains(uid)) return true;
        if (flag.Rollout == null) return null;
        var rollout = flag.Rollout.Value;
        if (rollout >= 100) return true;
        if (rollout <= 0 || uid.Length == 0) return false;
        return Bucket(key, uid) < rollout;
    }

    public bool IsEnabled(string key, string? user = null, bool fallback = false)
    {
        try
        {
            if (!core.IsOn("flags") || !core.Flags.TryGetValue(key, out var flag)) return fallback;
            return Evaluate(flag, key, user) ?? fallback;
        }
        catch (Exception)
        {
            return fallback;
        }
    }
}

/// <summary>The answer of a form check.</summary>
public sealed class FormCheck
{
    public bool Ok { get; set; } = true;
    public bool Spam { get; set; }
    public List<string> Reasons { get; set; } = new();
    public bool Checked { get; set; }
}

/// <summary>Form protection module: checks a form your server received before
/// you accept it (POST /collectanalytics/shield/verify, the same check as spam
/// protection's). It reads the hidden "analytics-shield" answer the tracker
/// puts in protected forms, and checks the email, name and text for fake
/// sign-ups. Passwords, card numbers and tokens are never sent. Fails open:
/// when the check can't be made, the form is accepted (Checked false).</summary>
internal sealed class Forms
{
    public const int MaxFields = 50;
    public const string AnswerField = "analytics-shield";
    // Fields never sent, by name: the same list as the other packages',
    // autocomplete's cc-number, cc-csc and cc-exp included. CheckAsync is
    // handed the whole form, so whoever adds it to a sign-up or a checkout
    // relies on this list: keep it wide. ("pass" also covers passwd and
    // passport.) Word edges are ASCII, as PHP's \b, so "éauth" reads alike everywhere.
    private const string Edge = "(?<![A-Za-z0-9_])", EdgeAfter = "(?![A-Za-z0-9_])";
    private static readonly System.Text.RegularExpressions.Regex PrivateField = new(
        "pass|pwd|card|cc[-_]?(num|no|number|csc|exp)|cvc|cvv|cvn|expiry|exp[-_]?(month|year|date)|secret|token|" + Edge + "auth" + EdgeAfter + "|authoriz|api[-_]?key|otp|mfa|2fa|"
        + Edge + "pin" + EdgeAfter + "|security[-_]?code|signature|private|ssn|sin" + EdgeAfter + "|nino|tax[-_]?id|iban|bic|swift|routing|account[-_]?(no|num|number)|dob|birth|licen[cs]e|csrf|nonce|analytics-shield",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    // A card number in a field nobody thought to name "card" still must not be
    // sent, so values are checked too: 13-19 digits that pass Luhn are taken out
    // of the text and the rest of the message is kept, so spam is still judged.
    private static readonly System.Text.RegularExpressions.Regex Digits = new(Edge + "(?:[0-9][ -]?){12,18}[0-9]" + EdgeAfter,
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private readonly Core core;

    public Forms(Core core)
    {
        this.core = core;
    }

    public static Dictionary<string, string> PlainFields(IEnumerable<KeyValuePair<string, string[]>> fields)
    {
        var output = new Dictionary<string, string>();
        foreach (var pair in fields.Take(MaxFields))
        {
            if (PrivateField.IsMatch(pair.Key)) continue;
            output[J.Clip(pair.Key, 100)] = WithoutCardNumbers(J.Clip(string.Join(", ", pair.Value.Where(v => v != null)), 2000));
        }
        return output;
    }

    /// <summary>Anything shaped like a card number, and passing Luhn, as
    /// [removed]. Luhn is what keeps order numbers and phone numbers readable.</summary>
    public static string WithoutCardNumbers(string text) => Digits.Replace(text, match =>
    {
        var sum = 0;
        var alt = false;
        for (var i = match.Value.Length - 1; i >= 0; i--)
        {
            var c = match.Value[i];
            if (c < '0' || c > '9') continue;
            var n = c - '0';
            if (alt)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alt = !alt;
        }
        return sum % 10 == 0 ? "[removed]" : match.Value;
    });

    public async Task<FormCheck> CheckAsync(IEnumerable<KeyValuePair<string, string[]>> fields, string? ip = "", string? email = null, string? name = null, string? form = null)
    {
        var unchecked_ = new FormCheck { Reasons = new List<string> { "unchecked" } };
        if (!core.IsOn("forms")) return new FormCheck();
        var all = fields.ToList();
        var token = all.FirstOrDefault(p => p.Key == AnswerField).Value;
        var body = new Dictionary<string, object?>
        {
            ["token"] = token != null && token.Length > 0 ? token[0] ?? "" : "",
            ["fields"] = PlainFields(all),
            ["ip"] = ip ?? "",
        };
        if (email != null) body["email"] = email;
        if (name != null) body["name"] = name;
        if (form != null) body["form"] = form;
        var res = await core.SendAsync("forms", "/collectanalytics/shield/verify", "POST", body).ConfigureAwait(false);
        if (res == null || res.Status >= 500 || res.Status == 403 || res.Status == 429)
        {
            if (res != null && res.Status == 403) core.Log("forms", "the site secret was refused; forms aren't checked");
            return unchecked_;
        }
        var data = res.Json();
        var spam = J.Prop(data, "success") is { ValueKind: JsonValueKind.False };
        return new FormCheck { Ok = !spam, Spam = spam, Reasons = J.Strings(J.Prop(data, "reasons")), Checked = true };
    }
}
