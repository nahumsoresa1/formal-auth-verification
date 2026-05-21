------------------------------ MODULE SecureLogin ------------------------------
EXTENDS Naturals, Sequences

(*
  Secure Authentication Protocol — Challenge-Response with Nonces
  ---------------------------------------------------------------
  Fix for the replay attack found in InsecureLogin.tla.

  The server now issues a fresh nonce (challenge) before accepting any
  credentials. The client must include the current session nonce in their
  response. Once the server accepts a nonce, it is permanently marked as
  used — so captured credentials from this session cannot be replayed.

  Threat model:
    - Passive attacker who can intercept any message on the network
    - Attacker attempts a cross-session replay: uses credentials captured
      from a completed session to authenticate in a new context
    - We are NOT modeling active MITM (that requires mutual authentication)

  Expected TLC result: NoReplay HOLDS — no violation found.
  Compare with InsecureLogin.tla where NoReplay is VIOLATED.
*)

CONSTANTS Password, Nonce

VARIABLES
  phase,            \* "idle" | "challenged" | "responded" | "done"
  nonceUsed,        \* TRUE once the server has consumed the nonce
  network,          \* messages on the wire
  loggedIn,         \* TRUE if any authentication succeeded
  authenticatedBy   \* "user" | "attacker" | "none"

vars == <<phase, nonceUsed, network, loggedIn, authenticatedBy>>

Init ==
  /\ phase           = "idle"
  /\ nonceUsed       = FALSE
  /\ network         = <<>>
  /\ loggedIn        = FALSE
  /\ authenticatedBy = "none"

\* ── Protocol steps ────────────────────────────────────────────────────────────

\* Step 1: Server sends a fresh nonce challenge to the client
ServerChallenge ==
  /\ phase    = "idle"
  /\ network' = Append(network, <<"challenge", Nonce>>)
  /\ phase'   = "challenged"
  /\ UNCHANGED <<nonceUsed, loggedIn, authenticatedBy>>

\* Step 2: Client responds with password + nonce
ClientRespond ==
  /\ phase    = "challenged"
  /\ network' = Append(network, <<"response", Password, Nonce>>)
  /\ phase'   = "responded"
  /\ UNCHANGED <<nonceUsed, loggedIn, authenticatedBy>>

\* Step 3: Server verifies — checks nonce is fresh, then marks it used
ServerVerify ==
  /\ phase      = "responded"
  /\ ~nonceUsed                   \* nonce must not have been used before
  /\ nonceUsed'       = TRUE      \* consume the nonce permanently
  /\ loggedIn'        = TRUE
  /\ authenticatedBy' = "user"
  /\ phase'           = "done"
  /\ UNCHANGED <<network>>

\* ── Attacker actions ──────────────────────────────────────────────────────────

\* Attacker intercepts any message — they learn password and nonce
AttackerIntercept ==
  /\ Len(network) > 0
  /\ UNCHANGED vars               \* passive observation only

\* Attacker attempts replay after session is done (cross-session replay attack)
\* Requires a FRESH nonce — but nonceUsed = TRUE once phase = "done"
\* Therefore this action is NEVER enabled after authentication completes.
\* This is what TLC formally verifies.
AttackerReplay ==
  /\ phase      = "done"          \* replay after the session ends
  /\ ~nonceUsed                   \* server requires a fresh nonce...
  /\ nonceUsed'       = TRUE      \* ...but it is already TRUE — action blocked
  /\ loggedIn'        = TRUE
  /\ authenticatedBy' = "attacker"
  /\ UNCHANGED <<phase, network>>

Next ==
  \/ ServerChallenge
  \/ ClientRespond
  \/ ServerVerify
  \/ AttackerIntercept
  \/ AttackerReplay

Spec == Init /\ [][Next]_vars

\* SECURITY PROPERTY: only the legitimate user can authenticate
\* TLC verifies this HOLDS — unlike InsecureLogin where it is violated
NoReplay == loggedIn => authenticatedBy = "user"

================================================================================
