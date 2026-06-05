------------------------------ MODULE OAuth2Fixed ------------------------------
EXTENDS Naturals, Sequences

(*
  OAuth 2.0 Authorization Code Flow with PKCE (RFC 7636)
  =======================================================
  PKCE = Proof Key for Code Exchange (pronounced "pixy")
  Published as RFC 7636 in 2015. Required for all public OAuth clients
  since OAuth 2.1 (2023).

  HOW PKCE WORKS:
  ---------------
  Before starting the flow, the client generates a secret:
    code_verifier  = random high-entropy string (never transmitted)
    code_challenge = SHA256(code_verifier) (sent with auth request)

  Modified flow:
    1. Client sends user to AuthServer with redirect_uri + code_challenge
    2. AuthServer stores code_challenge, redirects with code
    3. Client sends code + code_verifier to token endpoint
    4. AuthServer verifies SHA256(code_verifier) == stored code_challenge
    5. Only if they match → access_token issued

  WHY THE ATTACK FAILS:
  ---------------------
  The attacker intercepts the code (same as before).
  But to exchange it, they need code_verifier.
  code_verifier was NEVER transmitted — it stayed on the client.
  The attacker cannot produce a code_verifier that hashes to the stored
  code_challenge → the token exchange is rejected.

  SECURITY PROPERTY HOLDS:
    OnlyClientGetsToken == tokenHolder \in {"none", "client"}
*)

CONSTANTS Client, AuthServer, Attacker, ClientVerifier

VARIABLES
  phase,                 \* "idle" | "code_issued" | "done"
  storedChallenge,       \* code_challenge stored by the auth server
  codeOnWire,            \* TRUE when code is in the redirect URL
  codeUsed,              \* TRUE once code has been exchanged
  attackerHasCode,       \* TRUE if attacker intercepted the code
  attackerKnowsVerifier, \* TRUE if attacker knows code_verifier — stays FALSE
  tokenHolder            \* "none" | "client" | "attacker"

vars == <<phase, storedChallenge, codeOnWire, codeUsed,
          attackerHasCode, attackerKnowsVerifier, tokenHolder>>

\* TypeOK: type invariant for the PKCE-fixed protocol.
\* Per Lamport ch.4: a well-typed spec is the foundation of the inductive proof.
TypeOK ==
  /\ phase \in {"idle", "code_issued", "done"}
  /\ storedChallenge \in {"none"} \cup {ClientVerifier}
  /\ codeOnWire \in BOOLEAN
  /\ codeUsed \in BOOLEAN
  /\ attackerHasCode \in BOOLEAN
  /\ attackerKnowsVerifier \in BOOLEAN
  /\ tokenHolder \in {"none", "client", "attacker"}

Init ==
  /\ phase                = "idle"
  /\ storedChallenge      = "none"
  /\ codeOnWire           = FALSE
  /\ codeUsed             = FALSE
  /\ attackerHasCode      = FALSE
  /\ attackerKnowsVerifier = FALSE
  /\ tokenHolder          = "none"

\* ── Step 1: Client sends auth request with code_challenge ────────────────────
\* code_challenge = hash(ClientVerifier). The verifier itself is never sent.
AuthServerIssueCode ==
  /\ phase           = "idle"
  /\ storedChallenge' = ClientVerifier  \* server stores the challenge
  /\ codeOnWire'      = TRUE
  /\ phase'           = "code_issued"
  /\ UNCHANGED <<codeUsed, attackerHasCode, attackerKnowsVerifier, tokenHolder>>

\* ── Step 2: Attacker intercepts code from redirect URL ───────────────────────
\* Attacker gets the code — but code_verifier was never on the wire.
AttackerInterceptCode ==
  /\ codeOnWire       = TRUE
  /\ attackerHasCode' = TRUE
  /\ UNCHANGED <<phase, storedChallenge, codeOnWire, codeUsed,
                 attackerKnowsVerifier, tokenHolder>>

\* ── Step 3a: Legitimate client exchanges code + code_verifier ────────────────
\* Client sends code_verifier. Server checks hash(verifier) == storedChallenge.
\* Client knows ClientVerifier — check passes.
ClientExchangeCode ==
  /\ phase           = "code_issued"
  /\ ~codeUsed
  /\ storedChallenge = ClientVerifier   \* PKCE check: verifier matches challenge
  /\ codeUsed'    = TRUE
  /\ tokenHolder' = "client"
  /\ phase'       = "done"
  /\ UNCHANGED <<storedChallenge, codeOnWire, attackerHasCode, attackerKnowsVerifier>>

\* ── Step 3b: Attacker tries to exchange code — but needs code_verifier ───────
\* Attacker has the code but does NOT know code_verifier.
\* They cannot pass the PKCE check — this action is NEVER enabled.
AttackerExchangeCode ==
  /\ attackerHasCode      = TRUE
  /\ attackerKnowsVerifier = TRUE       \* attacker must know verifier...
  /\ ~codeUsed                          \* ...but attackerKnowsVerifier stays FALSE
  /\ codeUsed'    = TRUE
  /\ tokenHolder' = "attacker"
  /\ UNCHANGED <<phase, storedChallenge, codeOnWire, attackerHasCode, attackerKnowsVerifier>>

Next ==
  \/ AuthServerIssueCode
  \/ AttackerInterceptCode
  \/ ClientExchangeCode
  \/ AttackerExchangeCode

Spec == Init /\ [][Next]_vars

\* FairSpec: adds weak fairness so TLC can verify liveness properties.
\* Without fairness the model can stutter forever — <> properties require it
\* (Lamport, Specifying Systems, ch.8, temporal logic).
FairSpec == Spec /\ WF_vars(Next)

\* SECURITY PROPERTY — TLC verifies this HOLDS with PKCE applied
OnlyClientGetsToken == tokenHolder \in {"none", "client"}

\* LIVENESS PROPERTY: the client must eventually receive the token.
\* Holds because ClientExchangeCode is always eventually enabled and
\* AttackerExchangeCode is permanently blocked by its impossible guard.
EventuallyClientGetsToken == <>(tokenHolder = "client")

================================================================================
