# Q3/Q4 Keycloak 26.4.0 observations (realm-defender.json imported, client defender-api, confidential, secret dev-only-change-me, redirect http://localhost:8000/auth/callback, user without OTP/actions)
ISS in all redirects = http://<kc-host>:8080/realms/defender (here http://172.18.0.16:8080/realms/defender).

## Q3 login timeout
Realm JSON leaves all three null; admin API GET returns the applied defaults:
accessCodeLifespanLogin=1800, accessCodeLifespanUserAction=300, accessCodeLifespan=60 (ssoSessionIdleTimeout 1800, sslRequired external).
Set accessCodeLifespanLogin=60 (PUT 204). Opened form in a FRESH browser context, filled it, waited 65 s, submitted.
Result: NOT an error page and NOT a redirect to redirect_uri. A fresh login form, 200, at
 /realms/defender/login-actions/authenticate?client_id=defender-api&tab_id=<id>&client_data=<base64 of {"ru":redirect_uri,"rt":"code","st":"<original state>"}>
Page text: "Sign in to your account | Your login attempt timed out. Login will start from the beginning. | Username or email | Password | Sign In".
Resubmitting that form redirects to the callback with the ORIGINAL state (FRESH1), a code, and the original PKCE challenge still applies (code exchanged OK with the original verifier). So the flow restarts transparently.
(With an existing SSO session in the context the same timeout showed "Please re-authenticate to continue" instead, still a form.)
Form page has no <a> links (no cancel/back).

## Q4a callback on success
http://localhost:8000/auth/callback?state=<our state, echoed verbatim>&session_state=<uuid>&iss=<url-encoded issuer>&code=<uuid>.<uuid>.<uuid>
Order seen: state, session_state, iss, code. Example:
 state=STATE123
 session_state=00f29969-13bc-e7bb-8e7e-eaf73bc89a86 (uuid; equals token response session_state and sid claim)
 iss=http%3A%2F%2F172.18.0.16%3A8080%2Frealms%2Fdefender
 code=73127f75-e7c4-1dec-d998-4658de2f62b4.00f29969-13bc-e7bb-8e7e-eaf73bc89a86.c6bfc5bc-5bbe-49f7-ba73-6d6362ced06f (3 uuids joined by dots; 2nd = session_state, 3rd = client uuid)
No error params. Query, not fragment.

## Q4b error redirects (all redirect to redirect_uri, 302, query params, order error, error_description, state, iss)
- invalid scope "openid nosuchscope": error=invalid_scope&error_description=Invalid+scopes%3A+openid+nosuchscope&state=SB1&iss=...
- code_challenge_method=bogus: error=invalid_request&error_description=Invalid+parameter%3A+code+challenge+method+is+not+matching+the+configured+one&state=SB2&iss=...
- challenge params omitted (PKCE S256 required): error=invalid_request&error_description=Missing+parameter%3A+code_challenge_method&state=SB3&iss=...
- response_type=bogus: error=unsupported_response_type&state=SB4&iss=... (NO error_description)
- prompt=none with no session: not tested cleanly (my context had an SSO session, so it returned a code).
- unregistered redirect_uri: NO redirect; Keycloak HTML error page "We are sorry... Invalid parameter: redirect_uri" at the auth URL.
- The login form (and the timed-out form) contain no cancel/back link, so there is no user-cancel redirect (error=access_denied) to follow from the form.

## Q4c token exchange
POST {iss}/protocol/openid-connect/token, HTTP Basic client auth (client_id:secret), form fields: grant_type=authorization_code, code, code_verifier, redirect_uri.
200 JSON keys: access_token, expires_in(300), refresh_expires_in(1800), refresh_token, token_type("Bearer"), id_token, not-before-policy(0), session_state, scope("openid email profile"). Tokens are JWTs starting "eyJhbGciOi...".
ID token claims: exp, iat, auth_time, jti, iss, aud (client id), sub, typ=ID, azp, nonce (as sent), sid, at_hash, acr="1", email_verified, amr=["pwd"], name, preferred_username, given_name, family_name, email.
- Same code twice: 400 {"error":"invalid_grant","error_description":"Code not valid"}
- Wrong code_verifier: 400 {"error":"invalid_grant","error_description":"PKCE verification failed: Code mismatch"}; the code is then burned (right verifier afterwards -> 400 invalid_grant "Code not valid").
- Wrong redirect_uri: 400 {"error":"invalid_grant","error_description":"Incorrect redirect_uri"}
Scripts: q34.py, q3b.py; raw output q34.out, q3b.out.
