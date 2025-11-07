# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 5 |
| Low | 11 |
| Informational | 16 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Off-site Redirect | High | 1 |
| CSP: Failure to Define Directive with No Fallback | Medium | 12 |
| Content Security Policy (CSP) Header Not Set | Medium | 11 |
| Missing Anti-clickjacking Header | Medium | 11 |
| Source Code Disclosure - SQL | Medium | 2 |
| Vulnerable JS Library | Medium | 2 |
| Application Error Disclosure | Low | 1 |
| Cookie without SameSite Attribute | Low | 6 |
| Cross-Domain JavaScript Source File Inclusion | Low | 11 |
| Dangerous JS Functions | Low | 2 |
| Insufficient Site Isolation Against Spectre Vulnerability | Low | 11 |
| Permissions Policy Header Not Set | Low | 11 |
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low | 10 |
| Server Leaks Version Information via "Server" HTTP Response Header Field | Low | 1 |
| Strict-Transport-Security Header Not Set | Low | 2 |
| Timestamp Disclosure - Unix | Low | 1 |
| X-Content-Type-Options Header Missing | Low | 12 |
| Authentication Request Identified | Informational | 4 |
| Base64 Disclosure | Informational | 12 |
| Content-Type Header Missing | Informational | 1 |
| Information Disclosure - Suspicious Comments | Informational | 8 |
| Modern Web Application | Informational | 11 |
| Non-Storable Content | Informational | 2 |
| Re-examine Cache-control Directives | Informational | 1 |
| Retrieved from Cache | Informational | 2 |
| Sec-Fetch-Dest Header is Missing | Informational | 3 |
| Sec-Fetch-Mode Header is Missing | Informational | 3 |
| Sec-Fetch-Site Header is Missing | Informational | 3 |
| Sec-Fetch-User Header is Missing | Informational | 3 |
| Session Management Response Identified | Informational | 7 |
| Storable and Cacheable Content | Informational | 5 |
| Storable but Non-Cacheable Content | Informational | 3 |
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 7 |




## Alert Detail



### [ Off-site Redirect ](https://www.zaproxy.org/docs/alerts/10028/)



##### High (Medium)

### Description

Open redirects are one of the OWASP 2010 Top Ten vulnerabilities. This check looks at user-supplied input in query string parameters and POST data to identify where open redirects might be possible. Open redirects occur when an application allows user-supplied input (e.g. https://nottrusted.com) to control an off-site destination. This is generally a pretty accurate way to find where 301 or 302 redirects could be exploited by spammers or phishing attacks.

For example an attacker could supply a user with the following link: https://example.com/example.php?url=https://malicious.example.com.

NOTE: For the purposes of the passive check the authority portion of the origin and destination were compared. Manual testing may be required to validate the impact of this finding.

* URL: http://localhost:4000/learn%3Furl=https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras
  * Method: `GET`
  * Parameter: `url`
  * Attack: ``
  * Evidence: ``
  * Other Info: `The 301 or 302 response to a request for the following URL appeared to contain user input in the location header:

http://localhost:4000/learn?url=https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras

The user input found was:

url=https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras

The context was:

https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras`

Instances: 1

### Solution

To avoid the open redirect vulnerability, parameters of the application script/program must be validated before sending 302 HTTP code (redirect) to the client browser. Implement safe redirect functionality that only redirects to relative URI's, or a list of trusted domains.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
* [ https://cwe.mitre.org/data/definitions/601.html ](https://cwe.mitre.org/data/definitions/601.html)


#### CWE Id: [ 601 ](https://cwe.mitre.org/data/definitions/601.html)


#### WASC Id: 38

#### Source ID: 3

### [ CSP: Failure to Define Directive with No Fallback ](https://www.zaproxy.org/docs/alerts/10055/)



##### Medium (High)

### Description

The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.

* URL: http://localhost:4000/a
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/allocations/
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/app/views
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/div
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/h1
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/head
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/robots.txt
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/script
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/server.js
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/site/search%3Fvalue
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/sitemap.xml
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`
* URL: http://localhost:4000/span
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'`
  * Other Info: `The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.`

Instances: 12

### Solution

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Reference


* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://caniuse.com/#search=content+security+policy ](https://caniuse.com/#search=content+security+policy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)
* [ https://github.com/HtmlUnit/htmlunit-csp ](https://github.com/HtmlUnit/htmlunit-csp)
* [ https://web.dev/articles/csp#resource-options ](https://web.dev/articles/csp#resource-options)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a2
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a4
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a6
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 11

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://w3c.github.io/webappsec-csp/ ](https://w3c.github.io/webappsec-csp/)
* [ https://web.dev/articles/csp ](https://web.dev/articles/csp)
* [ https://caniuse.com/#feat=contentsecuritypolicy ](https://caniuse.com/#feat=contentsecuritypolicy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a2
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a3
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a4
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a5
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a6
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 11

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Source Code Disclosure - SQL ](https://www.zaproxy.org/docs/alerts/10099/)



##### Medium (Medium)

### Description

Application Source Code was disclosed by the web server. - SQL

* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `SELECT * FROM accounts WHERE username `
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `SELECT * FROM accounts WHERE username `
  * Other Info: ``

Instances: 2

### Solution

Ensure that application Source Code is not available with alternative extensions, and ensure that source code is not present within other files or data deployed to the web server, or served by the web server.

### Reference


* [ https://nhimg.org/twitter-breach ](https://nhimg.org/twitter-breach)


#### CWE Id: [ 540 ](https://cwe.mitre.org/data/definitions/540.html)


#### WASC Id: 13

#### Source ID: 3

### [ Vulnerable JS Library ](https://www.zaproxy.org/docs/alerts/10003/)



##### Medium (Medium)

### Description

The identified library appears to be vulnerable.

* URL: http://localhost:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `* Bootstrap v3.0.0`
  * Other Info: `The identified library bootstrap, version 3.0.0 is vulnerable.
CVE-2018-14041
CVE-2019-8331
CVE-2018-20677
CVE-2018-20676
CVE-2018-14042
CVE-2016-10735
CVE-2024-6485
https://nvd.nist.gov/vuln/detail/CVE-2024-6485
https://github.com/twbs/bootstrap/issues/28236
https://www.herodevs.com/vulnerability-directory/cve-2024-6485
https://github.com/advisories/GHSA-pj7m-g53m-7638
https://github.com/twbs/bootstrap/issues/20184
https://github.com/advisories/GHSA-vxmc-5x29-h64v
https://github.com/advisories/GHSA-ph58-4vrj-w6hr
https://github.com/twbs/bootstrap
https://github.com/twbs/bootstrap/issues/20631
https://github.com/advisories/GHSA-4p24-vmcr-4gqj
https://github.com/advisories/GHSA-9v3m-8fp8-mj99
https://nvd.nist.gov/vuln/detail/CVE-2018-20676
`
* URL: http://localhost:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/*! jQuery v1.10.2`
  * Other Info: `The identified library jquery, version 1.10.2 is vulnerable.
CVE-2020-11023
CVE-2020-11022
CVE-2015-9251
CVE-2019-11358
https://github.com/jquery/jquery/issues/2432
http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/
http://research.insecurelabs.org/jquery/test/
https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/
https://nvd.nist.gov/vuln/detail/CVE-2019-11358
https://github.com/advisories/GHSA-rmxg-73gg-4p98
https://nvd.nist.gov/vuln/detail/CVE-2015-9251
https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b
https://bugs.jquery.com/ticket/11974
https://github.com/jquery/jquery.com/issues/162
https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
`

Instances: 2

### Solution

Upgrade to the latest version of the affected library.

### Reference


* [ https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/ ](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)


#### CWE Id: [ 1395 ](https://cwe.mitre.org/data/definitions/1395.html)


#### Source ID: 3

### [ Application Error Disclosure ](https://www.zaproxy.org/docs/alerts/90022/)



##### Low (Medium)

### Description

This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.

* URL: http://localhost:4000/allocations/4%3Fthreshold=ZAP
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``

Instances: 1

### Solution

Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.

### Reference



#### CWE Id: [ 550 ](https://cwe.mitre.org/data/definitions/550.html)


#### WASC Id: 13

#### Source ID: 3

### [ Cookie without SameSite Attribute ](https://www.zaproxy.org/docs/alerts/10054/)



##### Low (Medium)

### Description

A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://localhost:4000/robots.txt
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://localhost:4000/sitemap.xml
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `set-cookie: connect.sid`
  * Other Info: ``

Instances: 6

### Solution

Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.

### Reference


* [ https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-same-site ](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-same-site)


#### CWE Id: [ 1275 ](https://cwe.mitre.org/data/definitions/1275.html)


#### WASC Id: 13

#### Source ID: 3

### [ Cross-Domain JavaScript Source File Inclusion ](https://www.zaproxy.org/docs/alerts/10017/)



##### Low (Medium)

### Description

The page includes one or more script files from a third-party domain.

* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a2
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a3
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a4
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a5
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a6
  * Method: `GET`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: `http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js`
  * Attack: ``
  * Evidence: `<script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'></" + "script>");</script>`
  * Other Info: ``

Instances: 11

### Solution

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

### Reference



#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### WASC Id: 15

#### Source ID: 3

### [ Dangerous JS Functions ](https://www.zaproxy.org/docs/alerts/10110/)



##### Low (Low)

### Description

A dangerous JS function seems to be in use that would leave the site vulnerable.

* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eval(`
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eval(`
  * Other Info: ``

Instances: 2

### Solution

See the references for security advice on the use of these functions.

### Reference


* [ https://v17.angular.io/guide/security ](https://v17.angular.io/guide/security)


#### CWE Id: [ 749 ](https://cwe.mitre.org/data/definitions/749.html)


#### Source ID: 3

### [ Insufficient Site Isolation Against Spectre Vulnerability ](https://www.zaproxy.org/docs/alerts/90004/)



##### Low (Medium)

### Description

Cross-Origin-Resource-Policy header is an opt-in header designed to counter side-channels attacks like Spectre. Resource should be specifically set as shareable amongst different origins.

* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/vendor/theme/font-awesome/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/vendor/theme/sb-admin.css
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 11

### Solution

Ensure that the application/web server sets the Cross-Origin-Resource-Policy header appropriately, and that it sets the Cross-Origin-Resource-Policy header to 'same-origin' for all web pages.
'same-site' is considered as less secured and should be avoided.
If resources must be shared, set the header to 'cross-origin'.
If possible, ensure that the end user uses a standards-compliant and modern web browser that supports the Cross-Origin-Resource-Policy header (https://caniuse.com/mdn-http_headers_cross-origin-resource-policy).

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 14

#### Source ID: 3

### [ Permissions Policy Header Not Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.

* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/tutorial/a5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 11

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy)
* [ https://developer.chrome.com/blog/feature-policy/ ](https://developer.chrome.com/blog/feature-policy/)
* [ https://scotthelme.co.uk/a-new-security-header-feature-policy/ ](https://scotthelme.co.uk/a-new-security-header-feature-policy/)
* [ https://w3c.github.io/webappsec-feature-policy/ ](https://w3c.github.io/webappsec-feature-policy/)
* [ https://www.smashingmagazine.com/2018/12/feature-policy/ ](https://www.smashingmagazine.com/2018/12/feature-policy/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) ](https://www.zaproxy.org/docs/alerts/10037/)



##### Low (Medium)

### Description

The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/vendor/theme/font-awesome/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: http://localhost:4000/vendor/theme/sb-admin.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``

Instances: 10

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.

### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework ](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
* [ https://www.troyhunt.com/shhh-dont-let-your-response-headers/ ](https://www.troyhunt.com/shhh-dont-let-your-response-headers/)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ Server Leaks Version Information via "Server" HTTP Response Header Field ](https://www.zaproxy.org/docs/alerts/10036/)



##### Low (High)

### Description

The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2025-12-18-09-14-51.chain
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `AmazonS3`
  * Other Info: ``

Instances: 1

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

### Reference


* [ https://httpd.apache.org/docs/current/mod/core.html#servertokens ](https://httpd.apache.org/docs/current/mod/core.html#servertokens)
* [ https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10) ](https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10))
* [ https://www.troyhunt.com/shhh-dont-let-your-response-headers/ ](https://www.troyhunt.com/shhh-dont-let-your-response-headers/)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ Strict-Transport-Security Header Not Set ](https://www.zaproxy.org/docs/alerts/10035/)



##### Low (High)

### Description

HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.

* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2025-12-18-09-14-51.chain
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/42520b78-dc12-495f-89bd-ce830a2c26c2
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 2

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)
* [ https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security ](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
* [ https://caniuse.com/stricttransportsecurity ](https://caniuse.com/stricttransportsecurity)
* [ https://datatracker.ietf.org/doc/html/rfc6797 ](https://datatracker.ietf.org/doc/html/rfc6797)


#### CWE Id: [ 319 ](https://cwe.mitre.org/data/definitions/319.html)


#### WASC Id: 15

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/42520b78-dc12-495f-89bd-ce830a2c26c2
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1748394604`
  * Other Info: `1748394604, which evaluates to: 2025-05-28 01:10:04.`

Instances: 1

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: http://localhost:4000/images/owasplogo.png
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/tutorial/a3
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/tutorial/a5
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/vendor/bootstrap/bootstrap.css
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/vendor/theme/font-awesome/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/vendor/theme/sb-admin.css
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: 12

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85) ](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85))
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=cJZqPHVwnNHUelQQ
passwordParam=password
referer=http://localhost:4000/login
csrfToken=_csrf`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=mwdWygpT
passwordParam=password
referer=http://localhost:4000/login
csrfToken=_csrf`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=mwdWygpTvmSmJNjH
passwordParam=password
referer=http://localhost:4000/login
csrfToken=_csrf`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=userName
userValue=ZAP
passwordParam=password
referer=http://localhost:4000/login
csrfToken=_csrf`

Instances: 4

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Base64 Disclosure ](https://www.zaproxy.org/docs/alerts/10094/)



##### Informational (Medium)

### Description

Base64 encoded data was disclosed by the application/web server. Note: in the interests of performance not all base64 strings in the response were analyzed individually, the entire response should be looked at by the analyst/security team/developer(s).

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3Aut2y3-dsfLUYHnHm5tFONGRwNyqS1NoL`
  * Other Info: `���-�v��Q��nm�FGr�-M�`
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3AGuTOdb6GagYPmtUpihsJUm2mEbTt042B`
  * Other Info: `��L�[�f�`��R����&�aN�8�`
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3A7JAgg8EI5J0WJSqYmRR-1CRbdPyg9YBn`
  * Other Info: `��<�I�bR���G�BE�O�X`
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3A9hDuvigRIw2BTypLIzRj5cO-cNghHVs4`
  * Other Info: `�a��0��3F>\;��ճ`
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3ApdG3XFtrj_G9DiLf8DEd-lBbeOdGWNS_`
  * Other Info: `�
]uŶ����-�ߥ��te�K`
* URL: http://localhost:4000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3AijCD3MU2-6xS7cj7V21Ji5ZffB0uzKw6`
  * Other Info: `��=�So��.܏�vԘ�e������`
* URL: http://localhost:4000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3ANAurGMcyJQmqIwZRukA5Sn_0RWEj_nck`
  * Other Info: `�@���s"P��0e����DV?�r`
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `com/bh-us-11/Sullivan/BH_US_11_Sullivan_Server_Side_WP`
  * Other Info: `r��n���u�+��+ڟ�G�D��_ҺYb���I��z�҉׿X`
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `com/bh-us-11/Sullivan/BH_US_11_Sullivan_Server_Side_WP`
  * Other Info: `r��n���u�+��+ڟ�G�D��_ҺYb���I��z�҉׿X`
* URL: http://localhost:4000/tutorial/a3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `org/images/c/c5/Unraveling_some_Mysteries_around_DOM-based_XSS`
  * Other Info: `��?�f�z����Rzڽ�b��g�3+-z���������3����y��I`
* URL: http://localhost:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `D27CDB6E-AE6D-11cf-96B8-444553540000`
  * Other Info: `n���:�uq���>�9�~x�M4`
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `3AYzOc-gl5BKSPNrIDmxoeqdASgR32jV7k`
  * Other Info: `�39Ϡ��JH�k 9���(�h��`

Instances: 12

### Solution

Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.

### Reference


* [ https://projects.webappsec.org/w/page/13246936/Information%20Leakage ](https://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 319 ](https://cwe.mitre.org/data/definitions/319.html)


#### WASC Id: 13

#### Source ID: 3

### [ Content-Type Header Missing ](https://www.zaproxy.org/docs/alerts/10019/)



##### Informational (Medium)

### Description

The Content-Type header was either missing or empty.

* URL: http://localhost:4000/research%3Fsymbol=ZAP&url=https%253A%252F%252Fzap.example.com
  * Method: `GET`
  * Parameter: `content-type`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 1

### Solution

Ensure each page is setting the specific and appropriate content-type value for the content being delivered.

### Reference


* [ https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85) ](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85))


#### CWE Id: [ 345 ](https://cwe.mitre.org/data/definitions/345.html)


#### WASC Id: 12

#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker.

* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `userName`
  * Other Info: `The following pattern was used: \bUSERNAME\b and was detected in likely comment: "//localhost:4000/login -X POST --data 'userName=vyva%0aError: alex moldovan failed $1,000,000 transaction&password=Admin_123&_cs", see evidence field for the suspicious comment/snippet.`
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `userName`
  * Other Info: `The following pattern was used: \bUSERNAME\b and was detected in likely comment: "//localhost:4000/login -X POST --data 'userName=vyva%0aError: alex moldovan failed $1,000,000 transaction&password=Admin_123&_cs", see evidence field for the suspicious comment/snippet.`
* URL: http://localhost:4000/tutorial/a2
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `user`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "// Create user document", see evidence field for the suspicious comment/snippet.`
* URL: http://localhost:4000/tutorial/a5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `from`
  * Other Info: `The following pattern was used: \bFROM\b and was detected in likely comment: "// Prevent opening page in frame or iframe to protect from clickjacking", see evidence field for the suspicious comment/snippet.`
* URL: http://localhost:4000/tutorial/a7
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `admin`
  * Other Info: `The following pattern was used: \bADMIN\b and was detected in likely comment: "//Middleware to check if user has admin rights", see evidence field for the suspicious comment/snippet.`
* URL: http://localhost:4000/tutorial/a9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `later`
  * Other Info: `The following pattern was used: \bLATER\b and was detected in likely comment: "//docs.npmjs.com/cli/v6/commands/npm-audit">npm audit</a> is a vulnerability scanner built into the npm CLI (version 6 or later)", see evidence field for the suspicious comment/snippet.`
* URL: http://localhost:4000/vendor/chart/raphael-min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `from`
  * Other Info: `The following pattern was used: \bFROM\b and was detected in likely comment: "//raphaeljs.com/","letter-spacing":0,opacity:1,path:"M0,0",r:0,rx:0,ry:0,src:"",stroke:"#000","stroke-dasharray":"","stroke-line", see evidence field for the suspicious comment/snippet.`
* URL: http://localhost:4000/vendor/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `username`
  * Other Info: `The following pattern was used: \bUSERNAME\b and was detected in likely comment: "//,En=/^([\w.+-]+:)(?:\/\/([^\/?#:]*)(?::(\d+)|)|)/,Sn=x.fn.load,An={},jn={},Dn="*/".concat("*");try{yn=o.href}catch(Ln){yn=a.cr", see evidence field for the suspicious comment/snippet.`

Instances: 8

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 615 ](https://cwe.mitre.org/data/definitions/615.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="#" class="dropdown-toggle" data-toggle="dropdown" style="font-size: larger"><i class="fa fa-info-circle"></i></a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A1 - Injection 
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-danger">Exploitability: EASY</span>
            <span class="label label-warning">Prevalence: COMMON</span>
            <span class="label label-warning">Detectability: AVERAGE</span>
            <span class="label label-danger">Technical Impact: SEVERE</span>
        </div>
    </div>
</div>


<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.
            </div>
        </div>
        <!--
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Real World Attack Incident Examples</h3>
            </div>
            <div class="panel-body">
                Screencast here ...
            </div>
        </div>
        -->
    </div>
</div>


<!-- accordions -->
<div class="panel-group" id="accordion">
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseOne">
                    <i class="fa fa-chevron-down"></i>A1 - 1 Server Side JS Injection
                </a>
            </h4>
        </div>
        <div id="collapseOne" class="panel-collapse collapse in">
            <div class="panel-body">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        When
                        <code>eval()</code>,
                        <code>setTimeout()</code>,
                        <code>setInterval()</code>,
                        <code>Function()</code>are used to process user provided inputs, it can be exploited by an attacker to inject and execute malicious JavaScript code on server.
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Web applications using the JavaScript
                            <code>eval()</code>function to parse the incoming data without any type of input validation are vulnerable to this attack. An attacker can inject arbitrary JavaScript code to be executed on the server. Similarly
                            <code>setTimeout()</code>, and
                            <code>setInterval()</code>functions can take code in string format as a first argument causing same issues as
                            <code>eval()</code>.
                        </p>
                        <p>This vulnerability can be very critical and damaging by allowing attacker to send various types of commands.</p>
                        <p>
                            <b>Denial of Service Attack:</b>
                        </p>
                        <iframe width="560" height="315" src="//www.youtube.com/embed/krOx9QWwcYw?rel=0" frameborder="0" allowfullscreen></iframe>
                        <p>
                            An effective denial-of-service attack can be executed simply by sending the commands below to
                            <code>eval()</code>function:
                        </p>


                        <pre>while(1)</pre>
                        <p>
                            This input will cause the target server's event loop to use 100% of its processor time and unable to process any other incoming requests until process is restarted.
                        </p>
                        <p>
                            An alternative DoS attack would be to simply exit or kill the running process:
                            <pre>process.exit()</pre> or <pre>process.kill(process.pid) </pre>
                        </p>
                        <p>
                            <b>File System Access</b>
                            <br/>
                        </p>
                        <iframe width="560" height="315" src="//www.youtube.com/embed/Mr-Jh9bjSLo?rel=0" frameborder="0" allowfullscreen></iframe>
                        <p>
                            Another potential goal of an attacker might be to read the contents of files from the server. For example, following two commands list the contents of the current directory and parent directory respectively:
                        </p>
                        <p>
                            <pre>res.end(require('fs').readdirSync('.').toString())</pre>
                            <pre>res.end(require('fs').readdirSync('..').toString()) </pre>
                        </p>
                        <p>
                            Once file names are obtained, an attacker can issue the command below to view the actual contents of a file:
                        </p>
                        <p>
                            <pre>res.end(require('fs').readFileSync(filename))</pre>
                        </p>
                        <p>
                            An attacker can further exploit this vulnerability by writing and executing harmful binary files using
                            <code>fs</code>and
                            <code>child_process</code>modules.
                        </p>
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        To prevent server-side js injection attacks:
                        <ul>
                            <li>Validate user inputs on server side before processing</li>
                            <li>Do not use
                                <code>eval()</code>function to parse user inputs. Avoid using other commands with similar effect, such as
                                <code>setTimeOut()</code>,
                                <code>setInterval()</code>, and
                                <code>Function()</code>.
                            </li>
                            <li>
                                For parsing JSON input, instead of using
                                <code>eval()</code>, use a safer alternative such as
                                <code>JSON.parse()</code>. For type conversions use type related
                                <code>parseXXX()</code>methods.
                            </li>
                            <li>Include
                                <code>"use strict"</code>at the beginning of a function, which enables <a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions_and_function_scope/Strict_mode"> strict mode </a>within the enclosing function scope.</li>

                        </ul>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p>In
                            <code>routes/contributions.js</code>, the
                            <code>handleContributionsUpdate()</code>function insecurely uses
                            <code>eval()</code>to convert user supplied contribution amounts to integer.
                            <pre>
        // Insecure use of eval() to parse inputs
        var preTax = eval(req.body.preTax);
        var afterTax = eval(req.body.afterTax);
        var roth = eval(req.body.roth);
                            </pre> This makes application vulnerable to SSJS attack. It can fixed simply by using
                            <code>parseInt()</code>instead.
                            <pre>
        //Fix for A1 -1 SSJS Injection attacks - uses alternate method to eval
        var preTax = parseInt(req.body.preTax);
        var afterTax = parseInt(req.body.afterTax);
        var roth = parseInt(req.body.roth);
                            </pre>
                        </p>
                        <p>In addition, all functions begin with
                            <code>use strict</code>pragma.
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Further Reading</h3>
                    </div>
                    <div class="panel-body">
                        <ul>
                            <li><a target="_blank" href="https://media.blackhat.com/bh-us-11/Sullivan/BH_US_11_Sullivan_Server_Side_WP.pdf">“ServerSide JavaScript Injection: Attacking NoSQL and Node.js"</a> a whitepaper by Bryan Sullivan.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /ssjs -->

    <!-- DB Injection -->
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseTwo">
                    <i class="fa fa-chevron-down"></i> A1 - 2 SQL and NoSQL Injection
                </a>
            </h4>
        </div>
        <div id="collapseTwo" class="panel-collapse">
            <div class="panel-body">


                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            SQL and NoSQL injections enable an attacker to inject code into the query that would be executed by the database. These flaws are introduced when software developers create dynamic database queries that include user supplied input.
                        </p>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>Both SQL and NoSQL databases are vulnerable to injection attack. Here is an example of equivalent attack in both cases, where attacker manages to retrieve admin user's record without knowing password:</p>
                        <h5>1. SQL Injection</h5>
                        <p>Lets consider an example SQL statement used to authenticate the user with username and password</p>
                        <pre>SELECT * FROM accounts WHERE username = '$username' AND password = '$password'</pre>
                        <p>If this statement is not prepared or properly handled when constructed, an attacker may be able to supply
                            <code>admin' --</code>in the username field to access the admin user's account bypassing the condition that checks for the password. The resultant SQL query would looks like:</p>
                        <pre>SELECT * FROM accounts WHERE username = 'admin' -- AND password = ''</pre>
                        <br/>
                        <h5>2. NoSQL Injection</h5>
                        <p>The equivalent of above query for NoSQL MongoDB database is:</p>
                        <pre>db.accounts.find({username: username, password: password});</pre>
                        <p>While here we are no longer dealing with query language, an attacker can still achieve the same results as SQL injection by supplying JSON input object as below:</p>
                        <pre>
{
    "username": "admin",
    "password": {$gt: ""}
}
                        </pre>
                        <p>In MongoDB,
                            <code>$gt</code>selects those documents where the value of the field is greater than (i.e. >) the specified value. Thus above statement compares password in database with empty string for greatness, which returns
                            <code>true</code>.</p>
                        <p>The same results can be achieved using other comparison operator such as
                            <code>$ne</code>.</p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">SSJS Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Server-side JavaScript Injection (SSJS) is an attack where JavaScript code is injected and executed in a server component. MongoDB specifically, is vulnerable to this attack when queries are run without proper sanitization.
                        </p>

                        <h5>$where operator</h5>
                        <p>
                            MongoDB's
                            <code>$where</code> operator performs JavaScript expression evaluation on the MongoDB server. If the user is able to inject direct code into such queries then such an attack can take place
                        </p>

                        <p>
                            Lets consider an example query:
                        </p>
                        <pre> db.allocationsCollection.find({ $where: "this.userId == '" + parsedUserId + "' && " + "this.stocks > " + "'" + threshold + "'" }); </pre>

                        <p>
                            The code will match all documents which have a
                            <code>userId</code> field as specified by
                            <code>parsedUserId</code> and a
                            <code>stocks</code> field as specified by
                            <code>threshold</code>. The problem is that these parameters are not validated, filtered, or sanitised, and vulnerable to SSJS Injection.
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        Here are some measures to prevent SQL / NoSQL injection attacks, or minimize impact if it happens:
                        <ul>
                            <li>Prepared Statements: For SQL calls, use prepared statements instead of building dynamic queries using string concatenation.</li>
                            <li>Input Validation: Validate inputs to detect malicious values. For NoSQL databases, also validate input types against expected types</li>
                            <li>Least Privilege: To minimize the potential damage of a successful injection attack, do not assign DBA or admin type access rights to your application accounts. Similarly minimize the privileges of the operating system account that the database process runs under.</li>
                        </ul>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p><strong>Note: These vulnerabilities are not present when using an Atlas M0 cluster with NodeGoat.</strong></p>
                        <p>The Allocations page of the demo application is vulnerable to NoSQL Injection. For example, set the stocks threshold filter to:</p>
                        <pre>1'; return 1 == '1</pre>
                        <p>This will retrieve allocations for all the users in the database.</p>
                        <p>An attacker could also send the following input for the
                            <code>threshold</code> field in the request's query, which will create a valid JavaScript expression and satisfy the
                            <code> $where</code> query as well, resulting in a DoS attack on the MongoDB server:
                        </p>
                        <pre>http://localhost:4000/allocations/2?threshold=5';while(true){};' </pre>
                        <p>
                            You can also just drop the following into the Stocks Threshold input box:
                        </p>
                        <pre>';while(true){};'</pre>
                        <p>For these vulnerabilities, bare minimum fixes can be found in
                        <code>allocations.html</code> and
                        <code>allocations-dao.js</code></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /NoSQL Injection -->

    <!-- Log Injection -->
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseThree">
                    <i class="fa fa-chevron-down"></i> A1 - 3 Log Injection
                </a>
            </h4>
        </div>
        <div id="collapseThree" class="panel-collapse">
            <div class="panel-body">


                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Log injection vulnerabilities enable an attacker to forge and tamper with an application's logs.
                        </p>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>An attacker may craft a malicious request that may deliberately fail, which the application will log, and when attacker's user input is unsanitized, the payload is sent as-is to the logging facility. Vulnerabilities may vary depending on the logging facility:</p>
                        <h5>1. Log Forging (CRLF) </h5>
                        <p>Lets consider an example where an application logs a failed attempt to login to the system. A very common example for this is as follows:
                        </p>
                        <pre>
var userName = req.body.userName;
console.log('Error: attempt to login with invalid user: ', userName);
                        </pre>
                        <p>When user input is unsanitized and the output mechanism is an ordinary terminal stdout facility then the application will be vulnerable to CRLF injection, where an attacker can create a malicious payload as follows:
                        <pre>
curl http://localhost:4000/login -X POST --data 'userName=vyva%0aError: alex moldovan failed $1,000,000 transaction&password=Admin_123&_csrf='
                        </pre>
                        Where the <code>userName</code> parameter is encoding in the request the LF symbol which will result in a new line to begin. Resulting log output will look as follows:
                        <pre>
Error: attempt to login with invalid user:  vyva
Error: alex moldovan failed $1,000,000 transaction
                        </pre>
                        <br/>
                        <h5>2. Log Injection Escalation </h5>
                        <p>
                            An attacker may craft malicious input in hope of an escalated attack where the target isn't the logs themselves, but rather the actual logging system. For example, if an application has a back-office web app that manages viewing and tracking the logs, then an attacker may send an XSS payload into the log, which may not result in log forging on the log itself, but when viewed by a system administrator on the log viewing web app then it may compromise it and result in XSS injection that if the logs app is vulnerable.
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">

                        As always when dealing with user input:
                        <ul>
                            <li>
                                Do not allow user input into logs
                            </li>
                            <li>
                                Encode to proper context, or sanitize user input
                            </li>
                        </ul>

                        Encoding example:
                        <pre>
// Step 1: Require a module that supports encoding
var ESAPI = require('node-esapi');
// - Step 2: Encode the user input that will be logged in the correct context
// following are a few examples:
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForHTML(userName));
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForJavaScript(userName));
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForURL(userName));
                        </pre>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p>For the above Log Injection vulnerability, example and fix can be found at
                        <code>routes/session.js</code></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /Log Injection -->

</div>
<!-- end accordions -->

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial/a1
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A1 - Injection 
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-danger">Exploitability: EASY</span>
            <span class="label label-warning">Prevalence: COMMON</span>
            <span class="label label-warning">Detectability: AVERAGE</span>
            <span class="label label-danger">Technical Impact: SEVERE</span>
        </div>
    </div>
</div>


<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.
            </div>
        </div>
        <!--
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Real World Attack Incident Examples</h3>
            </div>
            <div class="panel-body">
                Screencast here ...
            </div>
        </div>
        -->
    </div>
</div>


<!-- accordions -->
<div class="panel-group" id="accordion">
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseOne">
                    <i class="fa fa-chevron-down"></i>A1 - 1 Server Side JS Injection
                </a>
            </h4>
        </div>
        <div id="collapseOne" class="panel-collapse collapse in">
            <div class="panel-body">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        When
                        <code>eval()</code>,
                        <code>setTimeout()</code>,
                        <code>setInterval()</code>,
                        <code>Function()</code>are used to process user provided inputs, it can be exploited by an attacker to inject and execute malicious JavaScript code on server.
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Web applications using the JavaScript
                            <code>eval()</code>function to parse the incoming data without any type of input validation are vulnerable to this attack. An attacker can inject arbitrary JavaScript code to be executed on the server. Similarly
                            <code>setTimeout()</code>, and
                            <code>setInterval()</code>functions can take code in string format as a first argument causing same issues as
                            <code>eval()</code>.
                        </p>
                        <p>This vulnerability can be very critical and damaging by allowing attacker to send various types of commands.</p>
                        <p>
                            <b>Denial of Service Attack:</b>
                        </p>
                        <iframe width="560" height="315" src="//www.youtube.com/embed/krOx9QWwcYw?rel=0" frameborder="0" allowfullscreen></iframe>
                        <p>
                            An effective denial-of-service attack can be executed simply by sending the commands below to
                            <code>eval()</code>function:
                        </p>


                        <pre>while(1)</pre>
                        <p>
                            This input will cause the target server's event loop to use 100% of its processor time and unable to process any other incoming requests until process is restarted.
                        </p>
                        <p>
                            An alternative DoS attack would be to simply exit or kill the running process:
                            <pre>process.exit()</pre> or <pre>process.kill(process.pid) </pre>
                        </p>
                        <p>
                            <b>File System Access</b>
                            <br/>
                        </p>
                        <iframe width="560" height="315" src="//www.youtube.com/embed/Mr-Jh9bjSLo?rel=0" frameborder="0" allowfullscreen></iframe>
                        <p>
                            Another potential goal of an attacker might be to read the contents of files from the server. For example, following two commands list the contents of the current directory and parent directory respectively:
                        </p>
                        <p>
                            <pre>res.end(require('fs').readdirSync('.').toString())</pre>
                            <pre>res.end(require('fs').readdirSync('..').toString()) </pre>
                        </p>
                        <p>
                            Once file names are obtained, an attacker can issue the command below to view the actual contents of a file:
                        </p>
                        <p>
                            <pre>res.end(require('fs').readFileSync(filename))</pre>
                        </p>
                        <p>
                            An attacker can further exploit this vulnerability by writing and executing harmful binary files using
                            <code>fs</code>and
                            <code>child_process</code>modules.
                        </p>
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        To prevent server-side js injection attacks:
                        <ul>
                            <li>Validate user inputs on server side before processing</li>
                            <li>Do not use
                                <code>eval()</code>function to parse user inputs. Avoid using other commands with similar effect, such as
                                <code>setTimeOut()</code>,
                                <code>setInterval()</code>, and
                                <code>Function()</code>.
                            </li>
                            <li>
                                For parsing JSON input, instead of using
                                <code>eval()</code>, use a safer alternative such as
                                <code>JSON.parse()</code>. For type conversions use type related
                                <code>parseXXX()</code>methods.
                            </li>
                            <li>Include
                                <code>"use strict"</code>at the beginning of a function, which enables <a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions_and_function_scope/Strict_mode"> strict mode </a>within the enclosing function scope.</li>

                        </ul>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p>In
                            <code>routes/contributions.js</code>, the
                            <code>handleContributionsUpdate()</code>function insecurely uses
                            <code>eval()</code>to convert user supplied contribution amounts to integer.
                            <pre>
        // Insecure use of eval() to parse inputs
        var preTax = eval(req.body.preTax);
        var afterTax = eval(req.body.afterTax);
        var roth = eval(req.body.roth);
                            </pre> This makes application vulnerable to SSJS attack. It can fixed simply by using
                            <code>parseInt()</code>instead.
                            <pre>
        //Fix for A1 -1 SSJS Injection attacks - uses alternate method to eval
        var preTax = parseInt(req.body.preTax);
        var afterTax = parseInt(req.body.afterTax);
        var roth = parseInt(req.body.roth);
                            </pre>
                        </p>
                        <p>In addition, all functions begin with
                            <code>use strict</code>pragma.
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Further Reading</h3>
                    </div>
                    <div class="panel-body">
                        <ul>
                            <li><a target="_blank" href="https://media.blackhat.com/bh-us-11/Sullivan/BH_US_11_Sullivan_Server_Side_WP.pdf">“ServerSide JavaScript Injection: Attacking NoSQL and Node.js"</a> a whitepaper by Bryan Sullivan.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /ssjs -->

    <!-- DB Injection -->
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseTwo">
                    <i class="fa fa-chevron-down"></i> A1 - 2 SQL and NoSQL Injection
                </a>
            </h4>
        </div>
        <div id="collapseTwo" class="panel-collapse">
            <div class="panel-body">


                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            SQL and NoSQL injections enable an attacker to inject code into the query that would be executed by the database. These flaws are introduced when software developers create dynamic database queries that include user supplied input.
                        </p>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>Both SQL and NoSQL databases are vulnerable to injection attack. Here is an example of equivalent attack in both cases, where attacker manages to retrieve admin user's record without knowing password:</p>
                        <h5>1. SQL Injection</h5>
                        <p>Lets consider an example SQL statement used to authenticate the user with username and password</p>
                        <pre>SELECT * FROM accounts WHERE username = '$username' AND password = '$password'</pre>
                        <p>If this statement is not prepared or properly handled when constructed, an attacker may be able to supply
                            <code>admin' --</code>in the username field to access the admin user's account bypassing the condition that checks for the password. The resultant SQL query would looks like:</p>
                        <pre>SELECT * FROM accounts WHERE username = 'admin' -- AND password = ''</pre>
                        <br/>
                        <h5>2. NoSQL Injection</h5>
                        <p>The equivalent of above query for NoSQL MongoDB database is:</p>
                        <pre>db.accounts.find({username: username, password: password});</pre>
                        <p>While here we are no longer dealing with query language, an attacker can still achieve the same results as SQL injection by supplying JSON input object as below:</p>
                        <pre>
{
    "username": "admin",
    "password": {$gt: ""}
}
                        </pre>
                        <p>In MongoDB,
                            <code>$gt</code>selects those documents where the value of the field is greater than (i.e. >) the specified value. Thus above statement compares password in database with empty string for greatness, which returns
                            <code>true</code>.</p>
                        <p>The same results can be achieved using other comparison operator such as
                            <code>$ne</code>.</p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">SSJS Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Server-side JavaScript Injection (SSJS) is an attack where JavaScript code is injected and executed in a server component. MongoDB specifically, is vulnerable to this attack when queries are run without proper sanitization.
                        </p>

                        <h5>$where operator</h5>
                        <p>
                            MongoDB's
                            <code>$where</code> operator performs JavaScript expression evaluation on the MongoDB server. If the user is able to inject direct code into such queries then such an attack can take place
                        </p>

                        <p>
                            Lets consider an example query:
                        </p>
                        <pre> db.allocationsCollection.find({ $where: "this.userId == '" + parsedUserId + "' && " + "this.stocks > " + "'" + threshold + "'" }); </pre>

                        <p>
                            The code will match all documents which have a
                            <code>userId</code> field as specified by
                            <code>parsedUserId</code> and a
                            <code>stocks</code> field as specified by
                            <code>threshold</code>. The problem is that these parameters are not validated, filtered, or sanitised, and vulnerable to SSJS Injection.
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        Here are some measures to prevent SQL / NoSQL injection attacks, or minimize impact if it happens:
                        <ul>
                            <li>Prepared Statements: For SQL calls, use prepared statements instead of building dynamic queries using string concatenation.</li>
                            <li>Input Validation: Validate inputs to detect malicious values. For NoSQL databases, also validate input types against expected types</li>
                            <li>Least Privilege: To minimize the potential damage of a successful injection attack, do not assign DBA or admin type access rights to your application accounts. Similarly minimize the privileges of the operating system account that the database process runs under.</li>
                        </ul>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p><strong>Note: These vulnerabilities are not present when using an Atlas M0 cluster with NodeGoat.</strong></p>
                        <p>The Allocations page of the demo application is vulnerable to NoSQL Injection. For example, set the stocks threshold filter to:</p>
                        <pre>1'; return 1 == '1</pre>
                        <p>This will retrieve allocations for all the users in the database.</p>
                        <p>An attacker could also send the following input for the
                            <code>threshold</code> field in the request's query, which will create a valid JavaScript expression and satisfy the
                            <code> $where</code> query as well, resulting in a DoS attack on the MongoDB server:
                        </p>
                        <pre>http://localhost:4000/allocations/2?threshold=5';while(true){};' </pre>
                        <p>
                            You can also just drop the following into the Stocks Threshold input box:
                        </p>
                        <pre>';while(true){};'</pre>
                        <p>For these vulnerabilities, bare minimum fixes can be found in
                        <code>allocations.html</code> and
                        <code>allocations-dao.js</code></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /NoSQL Injection -->

    <!-- Log Injection -->
    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseThree">
                    <i class="fa fa-chevron-down"></i> A1 - 3 Log Injection
                </a>
            </h4>
        </div>
        <div id="collapseThree" class="panel-collapse">
            <div class="panel-body">


                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            Log injection vulnerabilities enable an attacker to forge and tamper with an application's logs.
                        </p>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>An attacker may craft a malicious request that may deliberately fail, which the application will log, and when attacker's user input is unsanitized, the payload is sent as-is to the logging facility. Vulnerabilities may vary depending on the logging facility:</p>
                        <h5>1. Log Forging (CRLF) </h5>
                        <p>Lets consider an example where an application logs a failed attempt to login to the system. A very common example for this is as follows:
                        </p>
                        <pre>
var userName = req.body.userName;
console.log('Error: attempt to login with invalid user: ', userName);
                        </pre>
                        <p>When user input is unsanitized and the output mechanism is an ordinary terminal stdout facility then the application will be vulnerable to CRLF injection, where an attacker can create a malicious payload as follows:
                        <pre>
curl http://localhost:4000/login -X POST --data 'userName=vyva%0aError: alex moldovan failed $1,000,000 transaction&password=Admin_123&_csrf='
                        </pre>
                        Where the <code>userName</code> parameter is encoding in the request the LF symbol which will result in a new line to begin. Resulting log output will look as follows:
                        <pre>
Error: attempt to login with invalid user:  vyva
Error: alex moldovan failed $1,000,000 transaction
                        </pre>
                        <br/>
                        <h5>2. Log Injection Escalation </h5>
                        <p>
                            An attacker may craft malicious input in hope of an escalated attack where the target isn't the logs themselves, but rather the actual logging system. For example, if an application has a back-office web app that manages viewing and tracking the logs, then an attacker may send an XSS payload into the log, which may not result in log forging on the log itself, but when viewed by a system administrator on the log viewing web app then it may compromise it and result in XSS injection that if the logs app is vulnerable.
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">

                        As always when dealing with user input:
                        <ul>
                            <li>
                                Do not allow user input into logs
                            </li>
                            <li>
                                Encode to proper context, or sanitize user input
                            </li>
                        </ul>

                        Encoding example:
                        <pre>
// Step 1: Require a module that supports encoding
var ESAPI = require('node-esapi');
// - Step 2: Encode the user input that will be logged in the correct context
// following are a few examples:
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForHTML(userName));
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForJavaScript(userName));
console.log('Error: attempt to login with invalid user: %s', ESAPI.encoder().encodeForURL(userName));
                        </pre>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p>For the above Log Injection vulnerability, example and fix can be found at
                        <code>routes/session.js</code></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /Log Injection -->

</div>
<!-- end accordions -->

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial/a2
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A2-Broken Authentication and Session Management 
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-warning">Exploitability: AVERAGE</span>
            <span class="label label-danger">Prevalence: WIDESPREAD</span>
            <span class="label label-warning">Detectability: AVERAGE</span>
            <span class="label label-danger">Technical Impact: SEVERE</span>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                <p>
                    In this attack, an attacker (who can be anonymous external attacker, a user with own account who may attempt to steal data from accounts, or an insider wanting to disguise his or her actions) uses leaks or flaws in the authentication or session management functions to impersonate other users. Application functions related to authentication and session management are often not implemented correctly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities.
                </p>
                <p>
                    Developers frequently build custom authentication and session management schemes, but building these correctly is hard. As a result, these custom schemes frequently have flaws in areas such as logout, password management, timeouts, remember me, secret question, account update, etc. Finding such flaws can sometimes be difficult, as each implementation is unique.
                </p>
            </div>

        </div>
        <!--
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Real World Attack Incident Examples</h3>
            </div>
            <div class="panel-body">
                Screencast here ...
            </div>
        </div>
-->
    </div>
</div>

<!-- accordions -->
<div class="panel-group" id="accordion">

    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseTwo">
                    <i class="fa fa-chevron-down"></i> A2 - 1 Session Management
                </a>
            </h4>
        </div>
        <div id="collapseTwo" class="panel-collapse collapse in">
            <div class="panel-body">

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        Session management is a critical piece of application security. It is broader risk, and requires developers take care of protecting session id, user credential secure storage, session duration, and protecting critical session data in transit.
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p><b>Scenario #1:</b> Application timeouts aren't set properly. User uses a public computer to access site. Instead of selecting “logout” the user simply closes the browser tab and walks away. Attacker uses the same browser an hour later, and that browser is still authenticated.</p>

                        <p><b>Scenario #2: </b>Attacker acts as a man-in-middle and acquires user's session id from network traffic. Then uses this authenticated session id to connect to application without needing to enter user name and password.</p>

                        <p><b>Scenario #3: </b>Insider or external attacker gains access to the system's password database. User passwords are not properly hashed, exposing every users' password to the attacker.</p>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        Session management related security issues can be prevented by taking these measures:
                        <ul>
                            <li>User authentication credentials should be protected when stored using hashing or encryption.</li>
                            <li>Session IDs should not be exposed in the URL (e.g., URL rewriting).</li>
                            <li>Session IDs should timeout. User sessions or authentication tokens should get properly invalidated during logout.</li>
                            <li>Session IDs should be recreated after successful login.</li>
                            <li>Passwords, session IDs, and other credentials should not be sent over unencrypted connections.</li>
                        </ul>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Examples</h3>
                    </div>
                    <div class="panel-body">
                        <p>In the insecure demo app, following issues exists:</p>
                        <h3>1. Protecting user credentials</h3>
                        <p>password gets stored in database in plain text . Here is related code in
                            <code>data/user-dao.js</code>
                            <code>addUser()</code>method:
                            <pre>
// Create user document
var user = {
    userName: userName,
    firstName: firstName,
    lastName: lastName,
    password: password //received from request param
};
                        </pre> To secure it, handle password storage in a safer way by using one way encryption using salt hashing as below:</p>
                        <pre>
// Generate password hash
var salt = bcrypt.genSaltSync();
var passwordHash = bcrypt.hashSync(password, salt);

// Create user document
var user = {
    userName: userName,
    firstName: firstName,
    lastName: lastName,
    password: passwordHash
};
                        </pre> This hash password can not be decrypted, hence more secure. To compare the password when user logs in, the user entered password gets converted to hash and compared with the hash in storage.

                        <pre>
if (bcrypt.compareSync(password, user.password)) {
    callback(null, user);
} else {
    callback(invalidPasswordError, null);
}
                        </pre> Note: The bcrypt module also provides asynchronous methods for creating and comparing hash.
                        <br/>
                        <br/>
                        <h3>2. Session timeout and protecting cookies in transit</h3>

                        <p>The insecure demo application does not contain any provision to timeout user session. The session stays active until user explicitly logs out.</p>

                        <p>In addition to that, the app does not prevent cookies being accessed in script, making application vulnerable to Cross Site Scripting (XSS) attacks. Also cookies are not prevented to get sent on insecure HTTP connection.</p>

                        <p>To secure the application:</p>
                        <p>1. Use session based timeouts, terminate session when browser closes.</p>
                        <pre>
// Enable session management using express middleware
app.use(express.cookieParser());
 </pre>
                        <p>2. In addition, sets
                            <code>HTTPOnly</code>HTTP header preventing cookies being accessed by scripts. The application used HTTPS secure connections, and cookies are configured to be sent only on Secure HTTPS connections by setting
                            <code>Secure</code>flag.
                            <pre>
app.use(express.session({
    secret: "s3Cur3",
    cookie: {
        httpOnly: true,
        secure: true
    }
}));
                        </pre>
                        </p>
                        <p>
                            3. When user clicks logout, destroy the session and session cookie
                            <pre>
req.session.destroy(function() {
    res.redirect("/");
});
                        </pre> Note: The example code uses
                            <code>MemoryStore</code>to manage session data, which is not designed for production environment, as it will leak memory, and will not scale past a single process. Use database based storage MongoStore or RedisStore for production. Alternatively, sessions can be managed using popular passport module.
                        <br/>
                        <br/>
                        <h3>3. Session hijacking</h3>

                        <p>The insecure demo application does not regenerate a new session id upon user's login, therefore rendering a vulnerability of session hijacking if an attacker is able to somehow steal the cookie with the session id and use it.

                        <p>Upon login, a security best practice with regards to cookies session management would be to regenerate the session id so that if an id was already created for a user on an insecure medium (i.e: non-HTTPS website or otherwise), or if an attacker was able to get their hands on the cookie id before the user logged-in, then the old session id will render useless as the logged-in user with new privileges holds a new session id now.
                    </p>

                        <p>To secure the application:</p>
                        <p>1. Re-generate a new session id upon login (and best practice is to keep regenerating them
upon requests or at least upon sensitive actions like a user's password reset.

                            Re-generate a session id as follows:
                            By wrapping the below code as a function callback for the method req.session.regenerate()
                            <pre>
req.session.regenerate(function() {

  req.session.userId = user._id;

  if (user.isAdmin) {
    return res.redirect("/benefits");
  } else {
    return res.redirect("/dashboard");
  }

})
                        </pre>
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Further Reading</h3>
                    </div>
                    <div class="panel-body">
                        <ul>
                            <li><a href="https://npmjs.org/package/helmet">Helmet</a> Security header middleware collection for express</li>
                            <li><a href="http://recxltd.blogspot.sg/2012/03/seven-web-server-http-headers-that.html">Seven Web Server HTTP Headers that Improve Web Application Security for Free</a>
                            </li>
                            <li><a href="http://passportjs.org/guide/authenticate/">Passport</a> authentication middleware</li>
                            <li><a href="http://en.wikipedia.org/wiki/Session_fixation">CWE-384: Session Fixation</a>
                            </li>
                        </ul>
                    </div>
                </div>

            </div>
        </div>
    </div>
    <!-- /Session Management -->

    <div class="panel panel-info">
        <div class="panel-heading">
            <h4 class="panel-title">
                <a data-toggle="collapse" data-parent="#accordion" href="#collapseOne">
                    <i class="fa fa-chevron-down"></i> A2 - 2 Password Guessing Attacks
                </a>
            </h4>
        </div>
        <div id="collapseOne" class="panel-collapse collapse in">
            <div class="panel-body">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Description</h3>
                    </div>
                    <div class="panel-body">
                        Implementing a robust minimum password criteria (minimum length and complexity) can make it difficult for attacker to guess password.
                    </div>
                </div>
                <!--  
                <div class="panel panel-info"> 
                    <div class="panel-heading"> 
                        <h3 class="panel-title">Attack Scenario Demo</h3> 
                    </div> 
                    <div class="panel-body"> 
                        Screencast showing how attack can manifest in the target application ... 
                    </div> 
                </div> 
                -->
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Attack Mechanics</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            The attacker can exploit this vulnerability by brute force password guessing, more likely using tools that generate random passwords.
                        </p>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">How Do I Prevent It?</h3>
                    </div>
                    <div class="panel-body">
                        <p><b>Password length</b>
                        </p>
                        <p>Minimum passwords length should be at least eight (8) characters long. Combining this length with complexity makes a password difficult to guess and/or brute force.</p>
                        <p><b>Password complexity</b>
                        </p>
                        <p>Password characters should be a combination of alphanumeric characters. Alphanumeric characters consist of letters, numbers, punctuation marks, mathematical and other conventional symbols.</p>
                        <p><b>Username/Password Enumeration</b>
                        </p>
                        <p>Authentication failure responses should not indicate which part of the authentication data was incorrect. For example, instead of "Invalid username" or "Invalid password", just use "Invalid username and/or password" for both. Error responses must be truly identical in both display and source code</p>

                        <p><b>Additional Measures</b>
                        </p>
                        <p>
                            <ul>
                                <li>For additional protection against brute forcing, enforce account disabling after an established number of invalid login attempts (e.g., five attempts is common). The account must be disabled for a period of time sufficient to discourage brute force guessing of credentials, but not so long as to allow for a denial-of-service attack to be performed.</li>
                                <li>Only send non-temporary passwords over an encrypted connection or as encrypted data, such as in an encrypted email. Temporary passwords associated with email resets may be an exception. Enforce the changing of temporary passwords on the next use. Temporary passwords and links should have a short expiration time.</li>
                            </ul>
                    </div>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Source Code Example</h3>
                    </div>
                    <div class="panel-body">
                        <p>
                            The demo application doesn't enforce strong password. In routes/session.js
                            <code>validateSignup()</code>method, the regex for password enforcement is simply <pre>var PASS_RE = /^.{1,20}$/;</pre>
                        </p>
                        <p>
                            A stronger password can be enforced using the regex below, which requires at least 8 character password with numbers and both lowercase and uppercase letters.
                            <pre>var PASS_RE =/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;</pre>
                        </p>
                        <p>
                            Another issue, in routes/session.js, the
                            <code>handleLoginRequest()</code>enumerated whether password was incorrect or user doesn't exist.This information can be valuable to an attacker with brute forcing attempts. This can be easily fixed using a generic error message such as "Invalid username and/or password".
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /Password Complexity -->


</div>
<!-- end accordions -->

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial/a3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A3-Cross-Site Scripting (XSS)
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-warning">Exploitability: AVERAGE</span>
            <span class="label label-danger">Prevalence: VERY WIDESPREAD</span>
            <span class="label label-danger">Detectability: EASY</span>
            <span class="label label-warning">Technical Impact: MODERATE</span>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-lg-12">

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                XSS flaws occur whenever an application takes untrusted data and sends it to a web browser without proper validation or escaping.
                XSS allows attackers to execute scripts in the victims' browser, which can access any cookies, session tokens,
                or other sensitive information retained by the browser, or redirect user to malicious sites.
            </div>
        </div>

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Attack Mechanics</h3>
            </div>
            <div class="panel-body">
                <p>
                    There are two types of XSS flaws:
                </p>

                <ol>
                    <li>Reflected XSS: The malicious data is echoed back by the server in an immediate response to an HTTP
                        request from the victim.</li>
                    <li>Stored XSS: The malicious data is stored on the server or on browser (using HTML5 local storage,
                        for example), and later gets embedded in HTML page provided to the victim.</li>
                </ol>

                <p>Each of reflected and stored XSS can occur on the server or on the client (which is also known as DOM
                    based XSS), depending on when the malicious data gets injected in HTML markup.</p>
            </div>
        </div>

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">How Do I Prevent It?</h3>
            </div>
            <div class="panel-body">
                <ol>
                    <li>
                        <p><b> Input validation and sanitization:</b> Input validation and data sanitization are the first
                            line of defense against untrusted data. Apply white list validation wherever possible.</p>
                    </li>
                    <li>
                        <p> <b> Output encoding for correct context: </b>When a browser is rendering HTML and any other associated
                            content like CSS, javascript etc., it follows different rendering rules for each context. Hence
                            <i>Context-sensitive output encoding</i> is absolutely critical for mitigating risk of XSS.</p>
                        Here are the details about applying correct encoding in each context:
                        <table class="table table-bordered table-hover">
                            <tbody>
                                <tr>
                                    <th>Context</th>
                                    <th>Code Sample</th>
                                    <th>Encoding Type</th>
                                </tr>
                                <tr>
                                    <td>HTML Entity</td>
                                    <td>&lt;span&gt;
                                        <span style="color:red;">UNTRUSTED DATA</span>&lt;/span&gt;</td>
                                    <td>Convert &amp; to &amp;amp;
                                        <br>Convert &lt; to &amp;lt;
                                        <br>Convert &gt; to &amp;gt;
                                        <br>Convert " to &amp;quot;
                                        <br>Convert ' to &amp;#x27;
                                        <br>Convert / to &amp;#x2F;
                                    </td>
                                </tr>
                                <tr>
                                    <td>HTML Attribute Encoding</td>
                                    <td>&lt;input type="text" name="fname" value="
                                        <span style="color:red;">UNTRUSTED DATA</span>"&gt;</td>
                                    <td>Except for alphanumeric characters, escape all characters with the HTML Entity &amp;#xHH;
                                        format, including spaces. (HH = Hex Value)
                                        <br/>
                                    </td>
                                </tr>
                                <tr>
                                    <td>URI Encoding</td>
                                    <td>&lt;a href="/site/search?value=
                                        <span style="color:red;">UNTRUSTED DATA</span>"&gt;clickme&lt;/a&gt;</td>
                                    <td>Except for alphanumeric characters, escape all characters with ASCII values less
                                        than 256 with the HTML Entity &amp;#xHH; format, including spaces. (HH = Hex Value)
                                        <br/>
                                    </td>
                                </tr>
                                <tr>
                                    <td>JavaScript Encoding</td>
                                    <td>&lt;script&gt;var currentValue='
                                        <span style="color:red;">UNTRUSTED DATA</span>';&lt;/script&gt;
                                        <br>&lt;script&gt;someFunction('
                                        <span style="color:red;">UNTRUSTED DATA</span>');&lt;/script&gt;
                                    </td>
                                    <td>Ensure JavaScript variables are quoted. Except for alphanumeric characters, escape
                                        all characters with ASCII values less than 256 with \uXXXX unicode escaping format
                                        (X = Integer), or in xHH (HH = HEX Value) encoding format.
                                    </td>
                                </tr>
                                <tr>
                                    <td>CSS Encoding</td>
                                    <td>&lt;div style="width:
                                        <span style="color:red;">UNTRUSTED DATA</span>;"&gt;Selection&lt;/div&gt;</td>
                                    <td>Except for alphanumeric characters, escape all characters with ASCII values less
                                        than 256 with the \HH (HH= Hex Value) escaping format.
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </li>
                    <li>
                        <p><b>HTTPOnly cookie flag:</b> Preventing all XSS flaws in an application is hard. To help mitigate
                            the impact of an XSS flaw on your site, set the HTTPOnly flag on session cookie and any custom
                            cookies that are not required to be accessed by JavaScript.
                        </p>
                    </li>
                    <li>
                        <p><b>Implement Content Security Policy (CSP):</b> CSP is a browser side mechanism which allows creating
                            whitelists for client side resources used by the web application, e.g. JavaScript, CSS, images,
                            etc. CSP via special HTTP header instructs the browser to only execute or render resources from
                            those sources. For example, the CSP header below allows content only from example site's own
                            domain (mydomain.com) and all its sub domains.
                            <pre>Content-Security-Policy: default-src 'self' *.mydomain.com</pre>

                        </p>
                    </li>
                    <li> <b>Apply encoding on both client and server side: </b> It is essential to apply encoding on both
                        client and server side to mitigate DOM based XSS attack, in which untrusted data never leaves the
                        browser.
                </ol>
                <p>Source: XSS Prevention Cheat Sheet[1]
                </p>
            </div>
        </div>
        <div id="source-code-example" class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Source Code Example</h3>
            </div>
            <div class="panel-body">
                <p>
                    The demo web application is vulnerable to stored XSS attack on profiles form. On form submit, the first and last name field
                    values are submitted to the server, and without any validation get saved in database. The values are
                    then sent back to the browser without proper escaping to be shown at the top right menu.
                </p>
                <iframe width="560" height="315" src="//www.youtube.com/embed/KvZ5jdg083M?rel=0" frameborder="0" allowfullscreen></iframe>

                <p>Two measures can be taken to mitigate XSS risk:

                    <ol>
                        <li>In
                            <code>server.js</code>, enable the HTML Encoding using template engine's auto escape flag.
                            <pre>
swig.init({
    root: __dirname + "/app/views",
    autoescape: true //default value
});
                            </pre>
                        </li>
                        <li>
                            Set HTTPOnly flag for session cookie while configuring the express session
                            <pre>
// Enable session management using express middleware
app.use(express.session({
    secret: "s3Cur3",
    cookie: {
        httpOnly: true,
        secure: true
    }
}));
                            </pre>
                        </li>
                    </ol>
                    There were no additional contexts that needed encoding on the demo page; otherwise, it is necessary to encode for correct
                    context depending on where data get placed at.

            </div>
        </div>

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Output Encoding Context</h3>
            </div>
            <div class="panel-body">
                <p>
                    An important observation when handling output encoding to prevent XSS is the notion of context.
                </p>

                <p>
                    When output encoding is performed, it must match the context in which it is being injected to. For example, if a user input
                    is being injected to an HTML element then it will require different encoding semantics to escape malicious
                    input than if it were injected to say an HTML attribute or a JavaScript context altogether (such as in
                    a script tag).
                </p>

                <p>
                    An example for how to take advantage and exploit this mis-understanding exists on the profile page. See code references in
                    <code>profile.js</code> and <code>profile.html</code>
                </p>
            </div>
        </div>

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Further Reading</h3>
            </div>
            <div class="panel-body">
                <ol>
                    <li>
                        <a href="https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet">XSS Prevention
                            Cheat Sheet</a>
                    </li>
                    <li>
                        <a href="https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting#Server_XS">Types of Cross-Site
                            Scripting
                        </a>
                    </li>
                    <li>
                        <a href="https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#STYLE_sheet ">XSS Filter
                            Evasion Cheat Sheet</a>
                    </li>
                    <li>
                        <a href="https://www.owasp.org/images/c/c5/Unraveling_some_Mysteries_around_DOM-based_XSS.pdf ">Unraveling
                            some of the Mysteries around DOM-based XSS</a>
                    </li>
                </ol>
            </div>
        </div>

    </div>
</div>

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial/a4
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A4-Insecure Direct Object References
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-danger">Exploitability: EASY</span>
            <span class="label label-warning">Prevalence: COMMON</span>
            <span class="label label-danger">Detectability: EASY</span>
            <span class="label label-warning">Technical Impact: MODERATE</span>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                A direct object reference occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, or database key. Without an access control check or other protection, attackers can manipulate these references to access unauthorized data.</div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Attack Mechanics</h3>
            </div>
            <div class="panel-body">
                <p>
                    If an applications uses the actual name or key of an object when generating web pages, and doesn't verify if the user is authorized for the target object, this can result in an insecure direct object reference flaw. An attacker can exploit such flaws by manipulating parameter values. Unless object references are unpredictable, it is easy for an attacker to access all available data of that type.
                </p>
                <p>
                    For example, the insure demo application uses userid as part of the url to access the allocations (/allocations/{id}). An attacker can manipulate id value and access other user's allocation information.
                    <iframe width="560" height="315" src="//www.youtube.com/embed/KFTRMw5F_eg?rel=0" frameborder="0" allowfullscreen></iframe>
                </p>
            </div>
        </div>

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">How Do I Prevent It?</h3>
            </div>
            <div class="panel-body">
                <ol>
                    <li>
                        <b>Check access: </b> Each use of a direct object reference from an untrusted source must include an access control check to ensure the user is authorized for the requested object.
                    </li>
                    <li>
                        <b>Use per user or session indirect object references:</b> Instead of exposing actual database keys as part of the access links, use temporary per-user indirect reference. For example, instead of using the resource’s database key, a drop down list of six resources authorized for the current user could use the numbers 1 to 6 or unique random numbers to indicate which value the user selected. The application has to map the per-user indirect reference back to the actual database key on the server.
                    </li>
                    <li> <b>Testing and code analysis:</b> Testers can easily manipulate parameter values to detect such flaws. In addition, code analysis can quickly show whether authorization is properly verified.
                    </li>
                </ol>
            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Source Code Example</h3>
            </div>
            <div class="panel-body">
                <p>
                    In
                    <code>routes/allocations.js</code>, the insecure application takes user id from url to fetch the allocations.
                    <pre>
    var userId = req.params.userId;
    allocationsDAO.getByUserId(userId, function(error, allocations) {

        if (error) return next(error);

        return res.render("allocations", allocations);
    });
                </pre>
                </p>
                <p>
                    A safer alternative is to always retrieve allocations for logged in user (using
                    <code>req.session.userId</code>)instead of taking it from url.
                </p>
            </div>
        </div>

    </div>
</div>

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial/a5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A5-Security Misconfiguration
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-danger">Exploitability: EASY</span>
            <span class="label label-warning">Prevalence: COMMON</span>
            <span class="label label-danger">Detectability: EASY</span>
            <span class="label label-warning">Technical Impact: MODERATE</span>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                <p>This vulnerability allows an attacker to accesses default accounts, unused pages, unpatched flaws, unprotected files and directories, etc. to gain unauthorized access to or knowledge of the system.</p>
                <p>Security misconfiguration can happen at any level of an application stack, including the platform, web server, application server, database, framework, and custom code.</p>
                <p>Developers and system administrators need to work together to ensure that the entire stack is configured properly.</p>
            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Attack Mechanics</h3>
            </div>
            <div class="panel-body">

                This vulnerability encompasses a broad category of attacks, but here are some ways attacker can exploit it:
                <ol>
                    <li>If application server is configured to run as root, an attacker can run malicious scripts (by exploiting eval family functions) or start new child processes on server</li>
                    <li>Read, write, delete files on file system. Create and run binary files</li>
                    <li>If the server is misconfigured to leak internal implementation details via cookie names or HTTP response headers, then attacker can use this information towards building site's risk profile and finding vulnerabilities
                    </li>
                    <li>If request body size is not limited, an attacker can upload large size of input payload, causing server to run out of memory, or make processor and event loop busy.</li>
                </ol>

            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">How Do I Prevent It?</h3>
            </div>
            <div class="panel-body">
                Here are some node.js and express specific configuration measures:
                <ul>
                    <li>
                        Use latest stable version of node.js and express (or other web framework you are using). Keep a watch on published vulnerabilities of these. The vulnerabilities for node.js and express.js can be found <a href="http://blog.nodejs.org/vulnerability/">here</a> and
                        <a href="http://expressjs.com/advanced/security-updates.html">here</a>, respectively.
                    </li>
                    <li>
                        Do not run application with root privileges. It may seem necessary to run as root user to access privileged ports such as 80. However, this can achieved either by starting server as root and then downgrading the non-privileged user after listening on port 80 is established, or using a separate proxy, or using port mapping.</li>
                    <li>
                        Review default in HTTP Response headers to prevent internal implementation disclosure.
                    </li>
                    <li>
                        Use generic session cookie names
                    </li>
                    <li>
                        Limit HTTP Request Body size by setting sensible size limits on each content type specific middleware (
                        <code>urlencoded, json, multipart</code>) instead of using aggregate
                        <code>limit</code>middleware. Include only required middleware. For example if application doesn't need to support file uploads, do not include multipart middleware.
                        <li>
                            If using multipart middleware, have a strategy to clean up temporary files generated by it. These files are not garbage collected by default, and an attacker can fill disk with such temporary files
                        </li>
                        <li>
                            Vet npm packages used by the application
                        </li>
                        <li>
                            Lock versions of all npm packages used, for example using <a href="https://www.npmjs.org/doc/cli/npm-shrinkwrap.html"> shrinkwarp</a>, to have full control over when to install a new version of the package.
                        </li>
                        <li>
                            Set security specific HTTP headers
                        </li>
                </ul>
            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Source Code Example</h3>
            </div>
            <div class="panel-body">
                <div>
                    <iframe width="560" height="315" src="//www.youtube.com/embed/lCpnVrD2Neg?rel=0" frameborder="0" allowfullscreen></iframe>
                </div>
                <p>The default HTTP header x-powered-by can reveal implementation details to an attacker. It can be taken out by including this code in
                    <code>server.js</code>
                    <pre>   
        app.disable("x-powered-by"); 
    </pre>
                </p>
                <p>The default session cookie name for express sessions can be changed by setting key attribute while creating express session.
                    <pre>
        app.use(express.session({
            secret: config.cookieSecret,
            key: "sessionId",
            cookie: {
                httpOnly: true,
                secure: true
            }
        }));
    </pre>
                </p>
                <p>The security related HTTP Headers can be added using helmet middleware as below
                    <pre>
        // Prevent opening page in frame or iframe to protect from clickjacking
        app.disable("x-powered-by");

        // Prevent opening page in frame or iframe to protect from clickjacking
        app.use(helmet.xframe());

        // Prevents browser from caching and storing page
        app.use(helmet.noCache());

        // Allow loading resources only from white-listed domains
        app.use(helmet.csp());

        // Allow communication only on HTTPS
        app.use(helmet.hsts());

        // Forces browser to only use the Content-Type set in the response header instead of sniffing or guessing it
        app.use(nosniff());

</pre>
                </p>
            </div>
        </div>
    </div>
</div>

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial/a6
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A6-Sensitive Data Exposure
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-default">Exploitability: DIFFICULT</span>
            <span class="label label-warning">Prevalence: COMMON</span>
            <span class="label label-danger">Detectability: AVERAGE</span>
            <span class="label label-danger">Technical Impact: SEVERE</span>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                This vulnerability allows an attacker to access sensitive data such as credit cards, tax IDs, authentication credentials, etc to conduct credit card fraud, identity theft, or other crimes. Losing such data can cause severe business impact and damage to the reputation. Sensitive data deserves extra protection such as encryption at rest or in transit, as well as special precautions when exchanged with the browser.
            </div>
        </div>

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Attack Mechanics</h3>
            </div>
            <div class="panel-body">
                <p>If a site doesn’t use SSL/TLS for all authenticated pages, an attacker can monitor network traffic (such as on open wireless network), and steals user's session cookie. Attacker can then replay this cookie and hijacks the user's session, accessing the user's private data.</p>
                <p>If an attacker gets access the application database, he or she can steal the sensitive information not encrypted, or encrypted with weak encryption algorithm</p>

            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">How Do I Prevent It?</h3>
            </div>
            <div class="panel-body">
                <ul>
                    <li>Use Secure HTTPS network protocol</li>
                    <li>Encrypt all sensitive data at rest and in transit</li>
                    <li>Don’t store sensitive data unnecessarily. Discard it as soon as possible.</li>
                    <li>Ensure strong standard algorithms and strong keys are used, and proper key management is in place.</li>
                    <li>Disable autocomplete on forms collecting sensitive data and disable caching for pages that contain sensitive data.</li>
                </ul>
            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Source Code Example</h3>
            </div>
            <div class="panel-body">
                <p>1.The insecure demo application uses HTTP connection to communicate with server. A secure HTTPS sever can be set using https module. This would need a private key and certificate. Here are source code examples from
                    <code>/server.js</code>
                    <pre>
// Load keys for establishing secure HTTPS connection
var fs = require("fs");
var https = require("https");
var path = require("path");
var httpsOptions = {
    key: fs.readFileSync(path.resolve(__dirname, "./app/cert/key.pem")),
    cert: fs.readFileSync(path.resolve(__dirname, "./app/cert/cert.pem"))
};
               </pre>
                </p>
                <p>2. Start secure HTTPS sever
                    <pre>
// Start secure HTTPS server
https.createServer(httpsOptions, app).listen(config.port, function() {
    console.log("Express https server listening on port " + config.port);
});
                </pre>
                </p>
                <p>
                    3. The insecure demo application stores users personal sensitive information in plain text. To fix it, The
                    <code>data/profile-dao.js</code>can be modified to use crypto module to encrypt and decrypt sensitive information as below:
                    <pre>
// Include crypto module
var crypto = require("crypto");

//Set keys config object
var config = {
    cryptoKey: "a_secure_key_for_crypto_here",
    cryptoAlgo: "aes256", // or other secure encryption algo here
    iv: ""
};

// Helper method create initialization vector
// By default the initialization vector is not secure enough, so we create our own
var createIV = function() {
    // create a random salt for the PBKDF2 function - 16 bytes is the minimum length according to NIST
    var salt = crypto.randomBytes(16);
    return crypto.pbkdf2Sync(config.cryptoKey, salt, 100000, 512, "sha512");
};

// Helper methods to encryt / decrypt
var encrypt = function(toEncrypt) {
    config.iv = createIV();
    var cipher = crypto.createCipheriv(config.cryptoAlgo, config.cryptoKey, config.iv);
    return cipher.update(toEncrypt, "utf8", "hex") + cipher.final("hex");
};

var decrypt = function(toDecrypt) {
    var decipher = crypto.createDecipheriv(config.cryptoAlgo, config.cryptoKey, config.iv);
    return decipher.update(toDecrypt, "hex", "utf8") + decipher.final("utf8");
};

// Encrypt values before saving in database
user.ssn = encrypt(ssn);
user.dob = encrypt(dob);

// Decrypt values to show on view
user.ssn = decrypt(user.ssn);
user.dob = decrypt(user.dob);
</pre>

                </p>
            </div>
        </div>


    </div>
</div>

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/tutorial/a8
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="../vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/tutorial"><b>OWASP Node Goat Tutorial:</b> Fixing OWASP Top 10 </a>
            </div>

            <!-- Collect the nav links, forms, and other content for toggling -->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul class="nav navbar-nav side-nav">
                    <li><a href="/tutorial/a1"><i class="fa fa-wrench"></i> A1 Injection</a>
                    </li>
                    <li><a href="/tutorial/a2"><i class="fa fa-wrench"></i> A2 Broken Auth</a>
                    </li>
                    <li><a href="/tutorial/a3"><i class="fa fa-wrench"></i> A3 XSS</a>
                    </li>
                    <li><a href="/tutorial/a4"><i class="fa fa-wrench"></i> A4 Insecure DOR</a>
                    </li>
                    <li><a href="/tutorial/a5"><i class="fa fa-wrench"></i> A5 Misconfig</a>
                    </li>
                    <li><a href="/tutorial/a6"><i class="fa fa-wrench"></i> A6 Sensitive Data</a>
                    </li>
                    <li><a href="/tutorial/a7"><i class="fa fa-wrench"></i> A7 Access Controls</a>
                    </li>
                    <li><a href="/tutorial/a8"><i class="fa fa-wrench"></i> A8 CSRF</a>
                    </li>
                    <li><a href="/tutorial/a9"><i class="fa fa-wrench"></i> A9 Insecure Components</a>
                    </li>
                    <li><a href="/tutorial/a10"><i class="fa fa-wrench"></i> A10 Redirects</a>
                    </li>
                    <li><a href="/tutorial/redos"><i class="fa"></i> ReDoS Attacks</a>
                    </li>
                    <li><a href="/tutorial/ssrf"><i class="fa"></i> SSRF</a>
                    </li>
                </ul>

                <ul class="nav navbar-nav navbar-right navbar-user">
                    <li><a href="/login"><i class="fa fa-power-off"></i> Exit</a>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <h1>A8-Cross-Site Request Forgery (CSRF) 
                        <small></small>
                    </h1>
                </div>
            </div>
            <!-- /.row -->
            
<div class="row">
    <div class="col-lg-12">
        <div class="bs-example" style="margin-bottom: 40px;">
            <span class="label label-warning">Exploitability: AVERAGE</span>
            <span class="label label-warning">Prevalence: COMMON</span>
            <span class="label label-danger">Detectability: EASY</span>
            <span class="label label-warning">Technical Impact: MODERATE</span>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-lg-12">

        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Description</h3>
            </div>
            <div class="panel-body">
                A CSRF attack forces a logged-on victim’s browser to send a forged HTTP request, including the victim’s session cookie and any other automatically included authentication information, to a vulnerable web application. This allows the attacker to force the victim’s browser to generate requests that the vulnerable application processes as legitimate requests from the victim.
            </div>
        </div>
        <!--
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Real World Attack Incident Examples</h3>
            </div>
            <div class="panel-body">
                Screencast here ...
            </div>
        </div>
-->
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Attack Mechanics</h3>
            </div>
            <div class="panel-body">
                <p>
                    As browsers automatically send credentials like session cookies with HTTP requests to the server where cookies were received from, attackers can create malicious web pages which generate forged requests that are indistinguishable from legitimate ones.</p>
                <p>For example, CSRF vulnerability can be exploited on profile form on the insecure demo application.</p>
                <iframe width="560" height="315" src="//www.youtube.com/embed/vRDykS_2y3I?rel=0" frameborder="0" allowfullscreen></iframe>
                <p>To exploit it:
                    <ol>
                        <li>An attacker would need to host a forged form like below on a malicious sever.
                            <pre>
    &lt;html lang="en"&gt;
    &lt;head&gt;&lt;/head&gt;
    	&lt;body&gt;
    		&lt;form method="POST" action="http://TARGET_APP_URL_HERE/profile"&gt;
    			&lt;h1&gt; You are about to win a brand new iPhone!&lt;/h1&gt;
    			&lt;h2&gt; Click on the win button to claim it...&lt;/h2&gt;
    			&lt;input type="hidden" name="bankAcc" value="9999999"/&gt;
    			&lt;input type="hidden" name="bankRouting" value="88888888"/&gt;
                                &lt;input type="submit" value="Win !!!"/&gt;
    		&lt;/form&gt;
    	&lt;/body&gt;
    &lt;/html&gt;
              </pre> Note: A sample app containing form for CSRF attack on NodeGoat app is available <a target="_blank" href="https://github.com/ckarande/nodegoat-csrf-attack">here</a>.
                        </li>
                        <li>Next, attacker would need to manage opening the form on logged in victim's browser and attract user to submit it. When user submits this form, it results in victim user's browser sending a malicious request to vulnerable server, causing CSRF attack.
                        </li>
                    </ol>
                </p>

            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">How Do I Prevent It?</h3>
            </div>
            <div class="panel-body">
                <p>Express csrf middleware provides a very effective way to deal with csrf attack. By default this middleware generates a token named "_csrf" which should be added to requests which mutate state (PUT, POST, DELETE), within a hidden form field, or query-string, or header fields.</p>
                <p>If using method-override middleware, it is very important that it is used before any middleware that needs to know the method of the request, including CSRF middleware. Otherwise an attacker can use non-state mutating methods (such as GET) to bypass the CSRF middleware checks, and use method override header to convert request to desired method.</p>
                <p>When form is submitted, the middleware checks for existence of token and validates it by matching to the generated token for the response-request pair. If tokens do not match, it rejects the request. Thus making it really hard for an attacker to exploit CSRF.
                </p>
            </div>
        </div>
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">Source Code Example</h3>
            </div>
            <div class="panel-body">
                The
                <code>server.js</code>includes the express CSRF middleware after session is initialized. Then creates a custom middleware to generate new token using
                <code>req.csrfToken();</code>and exposes it to view by setting it in
                <code>res.locals</code>
                <pre>
        //Enable Express csrf protection
        app.use(express.csrf());

        app.use(function(req, res, next) { 
            res.locals.csrftoken = req.csrfToken(); 
            next(); 
        }); </pre> Next, this token can be included in a hidden form field in
                <code>views/profile.html</code>as below.
                <pre>
    &lt;input type="hidden" name="_csrf" value="{{ csrftoken } }"&gt;</pre>
            </div>
        </div>
    </div>
</div>

        </div>
        <!-- /#page-wrapper -->

    </div>
    <!-- /#wrapper -->

    <script src="../vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="#" class="dropdown-toggle" data-toggle="dropdown" style="font-size: larger"><i class="fa fa-info-circle"></i></a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="/vendor/html5shiv.js"><![endif]-->
</head>

<body>

    <div id="wrapper">

        <!-- Sidebar -->
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <!-- Brand and toggle get grouped for better mobile display -->
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="/dashboard">
                    <span style="font-size: x-large">
                        <span class="fa fa-bullseye"></span>Retire<b>Easy</b>
                    </span>
                    <span style="font-size: medium">Employee Retirement Savings Management</span>
                </a>
            </div>

            <!--  Nav Links-->
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <!--  side nav -->
                <ul class="nav navbar-nav side-nav">
                    
                    <li><a id="dashboard-menu-link" href="/"><i class="fa fa-dashboard"></i> Dashboard</a>
                    </li>
                    <li><a id="contributions-menu-link" href="/contributions"><i class="fa fa-bar-chart-o"></i> Contributions</a>
                    </li>
                    <li><a id="allocations-menu-link" href="/allocations/4"><i class="fa fa-table"></i> Allocations</a>
                    </li>
                    <li><a id="memos-menu-link" href="/memos"><i class="fa fa-table"></i> Memos</a>
                    </li>
                    <li><a id="profile-menu-link" href="/profile"><i class="fa fa-user"></i> Profile</a>
                    </li>
                    <li><a id="learn-menu-link" target="_blank" href="/learn?url=https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras"><i class="fa fa-edit"></i> Learning Resources</a>
                    </li>
                    <li><a id="research-menu-link" href="/research"><i class="fa fa-table"></i> Research</a>
                    </li>
                    
                    <li><a id="logout-menu-link" href="/logout"><i class="fa fa-power-off"></i> Logout</a>
                    </li>
                </ul>

                <!-- top nav -->
                <ul class="nav navbar-nav navbar-right navbar-user">

                    <li class="dropdown user-dropdown">
                        <a href="#" class="dropdown-toggle" data-toggle="dropdown"><i class="fa fa-user"></i> ZAP ZAP <b class="caret"></b></a>
                        <ul class="dropdown-menu">
                            
                            <li><a href="/profile"><i class="fa fa-user"></i> Profile</a>
                            </li>
                            <li class="divider"></li>
                            
                            <li><a href="/logout"><i class="fa fa-power-off"></i> Log Out</a>
                            </li>
                        </ul>
                    </li>
                </ul>
            </div>
            <!-- /.navbar-collapse -->
        </nav>

        <div id="page-wrapper">

            <div class="row">
                <div class="col-lg-12">
                    <!-- <h1> <small>Dashboard</small></h1> -->
                    <ol class="breadcrumb">
                        <li class="active"><i class="fa"></i> Dashboard</li>
                    </ol>
                </div>
            </div>
            <!-- /.row -->

            
<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-danger">
            <div class="panel-heading">
                <div class="row">
                    <div class="col-xs-1">
                        <i class="fa fa-comments fa-5x"></i>
                    </div>
                    <div class="col-xs-11">
                        <p class="announcement-text">Experts recommend having <b>80%</b> income replacement saved for retirement. You are estimated to have <b>61%</b> income replacement given your current information and contribution rate.</p>
                        <p class="announcement-text">The amount you're contributing to your retirement plan really does matter. Consider changing your contribution rate.</p>
                    </div>
                </div>
            </div>
            <a href="/contributions">
                <div class="panel-footer announcement-bottom">
                    <div class="row">
                        <div class="col-xs-6">
                            Update Contributions
                        </div>
                        <div class="col-xs-6 text-right">
                            <i class="fa fa-arrow-circle-right"></i>
                        </div>
                    </div>
                </div>
            </a>
        </div>
    </div>
</div>
<div class="row">
    <div class="col-lg-4">
        <div class="panel panel-success">
            <div class="panel-heading">
                <div class="row">
                    <div class="col-xs-1">
                        <i class="fa fa-usd fa-5x"></i>
                    </div>
                    <div class="col-xs-11">
                        <p class="announcement-heading text-right">$89,925.12</p>
                        <p class="announcement-text">Total Retirement Savings</p>
                    </div>
                </div>
            </div>
            <a href="#">
                <div class="panel-footer announcement-bottom">
                    <div class="row">
                        <div class="col-xs-3">

                        </div>
                        <div class="col-xs-9 text-right">

                        </div>
                    </div>
                </div>
            </a>
        </div>
    </div>
    <div class="col-lg-4">
        <div class="panel panel-warning">
            <div class="panel-heading">
                <div class="row">
                    <div class="col-xs-1">
                        <i class="fa fa-check fa-5x"></i>
                    </div>
                    <div class="col-xs-11">
                        <p class="announcement-heading text-right">$20,600</p>
                        <p class="announcement-text">Required Retirement Income / Month</p>
                    </div>
                </div>
            </div>
            <a href="#">
                <div class="panel-footer announcement-bottom">

                </div>
            </a>
        </div>
    </div>
    <div class="col-lg-4">
        <div class="panel panel-danger">
            <div class="panel-heading">
                <div class="row">
                    <div class="col-xs-1">
                        <i class="fa fa-tasks fa-5x"></i>
                    </div>
                    <div class="col-xs-11">
                        <p class="announcement-heading text-right">$15,630</p>
                        <p class="announcement-text">Estimated Retirement Income / Month</p>
                    </div>
                </div>
            </div>
            <a href="#">
                <div class="panel-footer announcement-bottom">

                </div>
            </a>
        </div>
    </div>

</div>
<!-- /.row -->

<div class="row">
    <div class="col-lg-12">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title"><i class="fa fa-bar-chart-o"></i> Portfolio Performance Statistics</h3>
            </div>
            <div class="panel-body">
                <div id="morris-chart-area"></div>
            </div>
        </div>
    </div>
</div>
<!-- /.row -->




        </div>
        <!-- /#page-wrapper -->
    </div>
    <!-- /#wrapper -->

    <!-- Bootstrap core JavaScript -->
    <script src="/vendor/jquery.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`

Instances: 11

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``

Instances: 2

### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Re-examine Cache-control Directives ](https://www.zaproxy.org/docs/alerts/10015/)



##### Informational (Low)

### Description

The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.

* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/42520b78-dc12-495f-89bd-ce830a2c26c2
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=3600`
  * Other Info: ``

Instances: 1

### Solution

For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching ](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)
* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control)
* [ https://grayduck.mn/2021/09/13/cache-control-recommendations/ ](https://grayduck.mn/2021/09/13/cache-control-recommendations/)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### WASC Id: 13

#### Source ID: 3

### [ Retrieved from Cache ](https://www.zaproxy.org/docs/alerts/10050/)



##### Informational (Medium)

### Description

The content was retrieved from a shared cache. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/42520b78-dc12-495f-89bd-ce830a2c26c2
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2025-12-18-09-14-51.chain
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 612`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`

Instances: 2

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.rfc-editor.org/rfc/rfc9110.html ](https://www.rfc-editor.org/rfc/rfc9110.html)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### Source ID: 3

### [ Sec-Fetch-Dest Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Specifies how and where the data would be used. For instance, if the value is audio, then the requested resource must be audio data and not any other type of resource.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: `Sec-Fetch-Dest`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Dest`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `Sec-Fetch-Dest`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-Dest header is included in request headers.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Sec-Fetch-Mode Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Allows to differentiate between requests for navigating between HTML pages and requests for loading resources like images, audio etc.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: `Sec-Fetch-Mode`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Mode`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `Sec-Fetch-Mode`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-Mode header is included in request headers.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Mode ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Mode)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Sec-Fetch-Site Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Specifies the relationship between request initiator's origin and target's origin.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: `Sec-Fetch-Site`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: `Sec-Fetch-Site`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `Sec-Fetch-Site`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-Site header is included in request headers.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Sec-Fetch-User Header is Missing ](https://www.zaproxy.org/docs/alerts/90005/)



##### Informational (High)

### Description

Specifies if a navigation request was initiated by a user.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: `Sec-Fetch-User`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: `Sec-Fetch-User`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `Sec-Fetch-User`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 3

### Solution

Ensure that Sec-Fetch-User header is included in user initiated requests.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-User ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-User)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://localhost:4000
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `connect.sid`
  * Other Info: `cookie:connect.sid`
* URL: http://localhost:4000/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `connect.sid`
  * Other Info: `cookie:connect.sid`
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `connect.sid`
  * Other Info: `cookie:connect.sid`
* URL: http://localhost:4000/robots.txt
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `connect.sid`
  * Other Info: `cookie:connect.sid`
* URL: http://localhost:4000/sitemap.xml
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `connect.sid`
  * Other Info: `cookie:connect.sid`
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `connect.sid`
  * Other Info: `cookie:connect.sid`
* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `connect.sid`
  * Other Info: `cookie:connect.sid`

Instances: 7

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://localhost:4000/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://localhost:4000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://localhost:4000/signup
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://localhost:4000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://localhost:4000/tutorial
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`

Instances: 5

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users.

* URL: http://localhost:4000/vendor/bootstrap/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://localhost:4000/vendor/theme/font-awesome/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://localhost:4000/vendor/theme/sb-admin.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``

Instances: 3

### Solution



### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Controllable HTML Element Attribute (Potential XSS) ](https://www.zaproxy.org/docs/alerts/10031/)



##### Informational (Low)

### Description

This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.

* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `password`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://localhost:4000/login

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
password=ZAP

The user-controlled value was:
zap`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://localhost:4000/login

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
userName=cJZqPHVwnNHUelQQ

The user-controlled value was:
cjzqphvwnnhuelqq`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://localhost:4000/login

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
userName=mwdWygpT

The user-controlled value was:
mwdwygpt`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://localhost:4000/login

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
userName=mwdWygpTvmSmJNjH

The user-controlled value was:
mwdwygptvmsmjnjh`
* URL: http://localhost:4000/login
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://localhost:4000/login

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
userName=ZAP

The user-controlled value was:
zap`
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://localhost:4000/signup

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
userName=tIrcJVQj

The user-controlled value was:
tircjvqj`
* URL: http://localhost:4000/signup
  * Method: `POST`
  * Parameter: `userName`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://localhost:4000/signup

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
userName=tIrcJVQjKLCyoaho

The user-controlled value was:
tircjvqjklcyoaho`

Instances: 7

### Solution

Validate all input and sanitize output it before writing to any HTML attributes.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


#### CWE Id: [ 20 ](https://cwe.mitre.org/data/definitions/20.html)


#### WASC Id: 20

#### Source ID: 3


