------------------------------ MODULE NeedhamSchroeder ------------------------------
EXTENDS Naturals, FiniteSets

(*
  Needham-Schroeder Public Key Protocol (1978)
  =============================================
  Protocol steps:
    1.  A → B : {A, Na}_Kb      Alice sends her identity + nonce, encrypted for Bob
    2.  B → A : {Na, Nb}_Ka     Bob responds with both nonces, encrypted for Alice
    3.  A → B : {Nb}_Kb         Alice sends Bob's nonce back, encrypted for Bob

  After step 3, both parties share Na and Nb and believe they have
  authenticated each other.

  THE FLAW (Lowe 1995):
  ---------------------
  An attacker Eve can impersonate Alice to Bob using a parallel session:

    1.  A  → E  : {A, Na}_Ke     Alice starts a session with Eve
    2.  E  → B  : {A, Na}_Kb     Eve forwards to Bob, pretending to be Alice
    3.  B  → E  : {Na, Nb}_Ka    Bob responds to Alice — Eve intercepts
    4.  E  → A  : {Na, Nb}_Ka    Eve forwards to Alice (can't decrypt, just relays)
    5.  A  → E  : {Nb}_Ke        Alice completes her session with Eve
    6.  E  → B  : {Nb}_Kb        Eve decrypts, re-encrypts for Bob, completes attack
    7.  Bob now believes he completed authentication with Alice.
        Alice never initiated a session with Bob.

  SECURITY PROPERTY VIOLATED:
    Authentication == bPhase = "done" => aPartner = Bob
    (If Bob completed the protocol, Alice must have initiated with Bob)

  TLC finds this violation automatically by exploring all reachable states.
*)

CONSTANTS Alice, Bob, Eve, Na, Nb

VARIABLES
  aPhase,    \* Alice's state: "idle" | "waiting" | "done"
  aPartner,  \* who Alice initiated her session with
  bPhase,    \* Bob's state: "idle" | "waiting" | "done"
  eKnows,    \* set of nonces Eve has learned
  msgs       \* set of messages on the network

vars == <<aPhase, aPartner, bPhase, eKnows, msgs>>

Init ==
  /\ aPhase   = "idle"
  /\ aPartner = "none"
  /\ bPhase   = "idle"
  /\ eKnows   = {}
  /\ msgs     = {}

\* ── Step 1: Alice initiates with Eve (not Bob) ────────────────────────────────
\* Alice starts a session thinking she is talking to Eve.
\* She sends {Alice, Na} encrypted with Eve's key.
AliceInitWithEve ==
  /\ aPhase    = "idle"
  /\ aPhase'   = "waiting"
  /\ aPartner' = Eve
  /\ msgs'     = msgs \cup {[step |-> 1, from |-> Alice, to |-> Eve, na |-> Na]}
  /\ UNCHANGED <<bPhase, eKnows>>

\* ── Step 2a: Eve receives msg1, decrypts it (it is for her), learns Na ────────
\* Eve can read {Alice, Na}_Ke because she holds her own private key.
\* She then forwards msg1 to Bob, pretending it came directly from Alice.
EveForwardsToBob ==
  /\ [step |-> 1, from |-> Alice, to |-> Eve, na |-> Na] \in msgs
  /\ eKnows'  = eKnows \cup {Na}
  /\ msgs'    = msgs \cup {[step |-> 1, from |-> Alice, to |-> Bob, na |-> Na]}
  /\ UNCHANGED <<aPhase, aPartner, bPhase>>

\* ── Step 2b: Bob receives msg1, believes it is from Alice, sends msg2 ─────────
\* Bob generates Nb and responds: {Na, Nb} encrypted with Alice's key.
\* Bob now believes he is in a session with Alice.
BobResponds ==
  /\ bPhase   = "idle"
  /\ [step |-> 1, from |-> Alice, to |-> Bob, na |-> Na] \in msgs
  /\ bPhase'  = "waiting"
  /\ msgs'    = msgs \cup {[step |-> 2, from |-> Bob, to |-> Alice, na |-> Na, nb |-> Nb]}
  /\ UNCHANGED <<aPhase, aPartner, eKnows>>

\* ── Step 3a: Eve intercepts msg2 (encrypted for Alice — Eve cannot decrypt) ───
\* Eve cannot read {Na, Nb}_Ka, but she can forward it to Alice unchanged.
EveForwardsToAlice ==
  /\ [step |-> 2, from |-> Bob, to |-> Alice, na |-> Na, nb |-> Nb] \in msgs
  /\ msgs' = msgs \cup {[step |-> 2, from |-> Eve, to |-> Alice, na |-> Na, nb |-> Nb]}
  /\ UNCHANGED <<aPhase, aPartner, bPhase, eKnows>>

\* ── Step 3b: Alice receives msg2 from Eve, sees her own Na, trusts it ─────────
\* Alice decrypts, sees Na (which she issued), concludes the session is valid.
\* She sends {Nb} encrypted with Eve's key (her session partner).
\* NOTE: Alice does NOT verify who sent this — the protocol flaw.
AliceCompletes ==
  /\ aPhase   = "waiting"
  /\ [step |-> 2, from |-> Eve, to |-> Alice, na |-> Na, nb |-> Nb] \in msgs
  /\ aPhase'  = "done"
  /\ msgs'    = msgs \cup {[step |-> 3, from |-> Alice, to |-> Eve, nb |-> Nb]}
  /\ UNCHANGED <<aPartner, bPhase, eKnows>>

\* ── Step 4a: Eve receives msg3, decrypts it (for her), learns Nb ──────────────
\* Eve can read {Nb}_Ke. She now knows Nb and can complete Bob's session.
EveLearnNb ==
  /\ [step |-> 3, from |-> Alice, to |-> Eve, nb |-> Nb] \in msgs
  /\ eKnows'  = eKnows \cup {Nb}
  /\ msgs'    = msgs \cup {[step |-> 3, from |-> Eve, to |-> Bob, nb |-> Nb]}
  /\ UNCHANGED <<aPhase, aPartner, bPhase>>

\* ── Step 4b: Bob receives msg3 (from Eve), accepts Nb, completes protocol ─────
\* Bob sees the correct Nb, believes Alice completed authentication.
\* ATTACK COMPLETE: Bob thinks he authenticated with Alice. He did not.
BobCompletes ==
  /\ bPhase  = "waiting"
  /\ [step |-> 3, from |-> Eve, to |-> Bob, nb |-> Nb] \in msgs
  /\ bPhase' = "done"
  /\ UNCHANGED <<aPhase, aPartner, eKnows, msgs>>

Next ==
  \/ AliceInitWithEve
  \/ EveForwardsToBob
  \/ BobResponds
  \/ EveForwardsToAlice
  \/ AliceCompletes
  \/ EveLearnNb
  \/ BobCompletes

Spec == Init /\ [][Next]_vars

\* SECURITY PROPERTY:
\* If Bob completed the protocol, Alice must have initiated with Bob directly.
\* TLC VIOLATES this — Bob completes but Alice's partner is Eve, not Bob.
Authentication == bPhase = "done" => aPartner = Bob

================================================================================
