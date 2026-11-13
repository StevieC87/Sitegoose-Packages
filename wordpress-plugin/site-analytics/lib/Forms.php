<?php
// Form protection module: checks a form your server received before you
// accept it (POST /collectanalytics/shield/verify, the same check as spam
// protection's). It reads the hidden "analytics-shield" answer the tracker
// puts in protected forms, and checks the email, name and text for fake
// sign-ups. Spam lands in the site's spam folder (Leads → Spam). Passwords,
// card numbers and tokens are never sent. Fails open: when the check can't be
// made, the form is accepted ('checked' => false). Waits for the answer (up
// to 4 seconds).

namespace AnalyticsPlatform;

class Forms
{
    // Fields never sent, by name. ProtectForm hands over the whole request, so
    // whoever adds it to a sign-up or a checkout route relies on this list:
    // keep it wide. (`pass` also covers passwd and passport.)
    const PRIVATE_FIELD = '/pass|pwd|card|cc_?(num|no|number)|cvc|cvv|cvn|expiry|exp_?(month|year|date)|secret|token|\bauth\b|authoriz|api_?key|otp|mfa|2fa|\bpin\b|security_?code|signature|private|ssn|sin\b|nino|tax_?id|iban|bic|swift|routing|account_?(no|num|number)|dob|birth|licen[cs]e|csrf|nonce|analytics-shield/i';
    // A card number in a field nobody thought to name "card" still must not be
    // sent, so values are checked too: 13-19 digits that pass Luhn are taken out
    // of the text and the rest of the message is kept, so spam is still judged.
    const DIGITS = '/\b(?:\d[ -]?){12,18}\d\b/';
    const MAX_FIELDS = 50;
    const ANSWER = 'analytics-shield';

    private $core;

    public function __construct(Core $core)
    {
        $this->core = $core;
    }

    public static function plainFields(array $fields)
    {
        $out = array();
        foreach (array_slice($fields, 0, self::MAX_FIELDS, true) as $label => $value) {
            if (preg_match(self::PRIVATE_FIELD, (string) $label)) {
                continue;
            }
            if (is_array($value)) {
                $value = implode(', ', array_filter($value, 'is_string'));
            }
            if (is_string($value) || is_numeric($value)) {
                $out[substr((string) $label, 0, 100)] = self::withoutCardNumbers(substr((string) $value, 0, 2000));
            }
        }
        return $out;
    }

    // Replaces anything shaped like a card number, and passing Luhn, with
    // [removed]. Luhn is what keeps order numbers and phone numbers readable.
    public static function withoutCardNumbers($text)
    {
        return preg_replace_callback(self::DIGITS, function ($match) {
            $digits = preg_replace('/\D/', '', $match[0]);
            $sum = 0;
            $alt = false;
            for ($i = strlen($digits) - 1; $i >= 0; $i--) {
                $n = (int) $digits[$i];
                if ($alt) {
                    $n *= 2;
                    if ($n > 9) {
                        $n -= 9;
                    }
                }
                $sum += $n;
                $alt = !$alt;
            }
            return $sum % 10 === 0 ? '[removed]' : $match[0];
        }, (string) $text);
    }

    // $fields: the form (default $_POST); $ip: the visitor's address.
    // Returns array('ok', 'spam', 'reasons', 'checked').
    public function check(array $fields, $ip = '', $email = null, $name = null, $form = null)
    {
        $unchecked = array('ok' => true, 'spam' => false, 'reasons' => array('unchecked'), 'checked' => false);
        if (!$this->core->isOn('forms')) {
            return array('ok' => true, 'spam' => false, 'reasons' => array(), 'checked' => false);
        }
        $body = array(
            'token' => isset($fields[self::ANSWER]) && is_string($fields[self::ANSWER]) ? $fields[self::ANSWER] : '',
            'fields' => (object) self::plainFields($fields),
            'ip' => (string) $ip,
        );
        foreach (array('email' => $email, 'name' => $name, 'form' => $form) as $key => $value) {
            if (is_string($value)) {
                $body[$key] = $value;
            }
        }
        $res = $this->core->http('POST', '/collectanalytics/shield/verify', $body, array(), 'body');
        // A verdict, spam or not, is always a 200. Anything else (unreachable,
        // a wrong secret, a request it couldn't read, over the limit) judged
        // nothing, and must not look like protection that works.
        $data = $res['status'] === 200 ? json_decode($res['body'], true) : null;
        if (!is_array($data) || !isset($data['success'])) {
            return $unchecked;
        }
        $spam = $data['success'] === false;
        return array(
            'ok' => !$spam,
            'spam' => $spam,
            'reasons' => isset($data['reasons']) && is_array($data['reasons']) ? $data['reasons'] : array(),
            'checked' => true,
        );
    }
}
