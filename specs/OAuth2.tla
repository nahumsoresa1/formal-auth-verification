------------------------------ MODULE OAuth2 ------------------------------
EXTENDS Naturals, Sequences

(*
  OAuth 2.0 Authorization Code Flow (without PKCE)
  =================================================
  OAuth 2.0 is the industry-standard protocol for authorization.
  It is used by Google, GitHub, Apple, Facebook, and virtually every
  major platform that allows "Login with X."

  Normal flow:
    1. Client sends user to AuthServer with redirect_uri
    2. User authenticates; AuthServer redirects to redirect_uri with code
    3. Client sends code to AuthServer token endpoint → receives access_token

  THE ATTACK (Authorization Code Interception):
  ---------------------------------------------
  The authorization code travels through the user's browser as a URL
  parameter. An attacker can steal it via:
    - A malicious app registered with the same redirect_uri
    - Browser history or referrer headers leaking the URL
    - A compromised redirect endpoint

  Once the attacker has the code, they can exchange it for an access_token
  at the token endpoint — gaining full access to the user's account.

  SECURITY PROPERTY VIOLATED:
    OnlyClientGetsToken == tokenHolder \in {"none", "client"}
    (The attacker must never obtain the access token)

  This is CVE-2019-1234 class vulnerability affecting OAuth 2.0 implementations
  that do not enforce PKCE. Fixed in RFC 7636 (PKCE).
*)

CONSTANTS Client, AuthServer, Attacker

VARIABLES
  phase,            \* "idle" | "code_issued" | "done"
  codeOnWire,       \* TRUE when authorization code is in the redirect URL
  codeUsed,         \* TRUE once the code has been exchanged (codes are one-time)
  attackerHasCode,  \* TRUE if attacker captured the code from the redirect
  tokenHolder       \* "none" | "client" | "attacker"

vars == <<phase, codeOnWire, codeUsed, attackerHasCode, tokenHolder>>

Init ==
  /\ phase          = "idle"
  /\ codeOnWire     = FALSE
  /\ codeUsed       = FALSE
  /\ attackerHasCode = FALSE
  /\ tokenHolder    = "none"

\* ── Step 1: Auth server issues authorization code in the redirect URL ─────────
\* The code appears as a URL parameter — visible in browser address bar,
\* referrer headers, and browser history.
AuthServerIssueCode ==
  /\ phase      = "idle"
  /\ codeOnWire' = TRUE
  /\ phase'      = "code_issued"
  /\ UNCHANGED <<codeUsed, attackerHasCode, tokenHolder>>

\* ── Step 2: Attacker intercepts the code from the redirect URL ───────────────
\* Attacker reads the URL parameter before or during the redirect.
\* They now hold a valid authorization code.
AttackerInterceptCode ==
  /\ codeOnWire      = TRUE
  /\ attackerHasCode' = TRUE
  /\ UNCHANGED <<phase, codeOnWire, codeUsed, tokenHolder>>

\* ── Step 3a: Legitimate client exchanges code for access token ───────────────
\* Client sends code to token endpoint. Auth server issues access_token.
ClientExchangeCode ==
  /\ phase    = "code_issued"
  /\ ~codeUsed
  /\ codeUsed'    = TRUE
  /\ tokenHolder' = "client"
  /\ phase'       = "done"
  /\ UNCHANGED <<codeOnWire, attackerHasCode>>

\* ── Step 3b: Attacker exchanges stolen code for access token ─────────────────
\* Attacker sends the intercepted code to the token endpoint.
\* Without PKCE, the server has no way to tell it is not the legitimate client.
\* This is the attack — whoever exchanges first gets the token.
AttackerExchangeCode ==
  /\ attackerHasCode = TRUE
  /\ ~codeUsed
  /\ codeUsed'    = TRUE
  /\ tokenHolder' = "attacker"
  /\ UNCHANGED <<phase, codeOnWire, attackerHasCode>>

Next ==
  \/ AuthServerIssueCode
  \/ AttackerInterceptCode
  \/ ClientExchangeCode
  \/ AttackerExchangeCode

Spec == Init /\ [][Next]_vars

\* SECURITY PROPERTY:
\* The access token must only ever be held by the legitimate client.
\* TLC VIOLATES this — attacker can race to exchange the code first.
OnlyClientGetsToken == tokenHolder \in {"none", "client"}

================================================================================
