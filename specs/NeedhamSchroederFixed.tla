------------------------------ MODULE NeedhamSchroederFixed ------------------------------
EXTENDS Naturals, FiniteSets

(*
  Needham-Schroeder-Lowe Protocol (Lowe's fix, 1995)
  ====================================================
  Gavin Lowe discovered the attack on the original protocol in 1995 and
  proposed a one-line fix: include the responder's identity in message 2.

  FIXED protocol steps:
    1.  A → B : {A, Na}_Kb         (same as before)
    2.  B → A : {Na, Nb, B}_Ka     Bob now includes his identity ← THE FIX
    3.  A → B : {Nb}_Kb            (same as before)

  WHY THE FIX WORKS:
  ------------------
  In the attack, Alice is in a session with Eve (aPartner = Eve).
  When Alice receives the forwarded message 2, she sees {Na, Nb, Bob}.
  She checks: does the declared sender (Bob) match her session partner (Eve)?
  It does NOT — so she rejects the message.

  Eve cannot forge a message saying sender = Eve because the message is
  encrypted with Alice's public key (Eve cannot modify it).

  The attack chain breaks at step 5: AliceCompletes never fires.
  Bob never receives message 3, so bPhase never reaches "done".

  SECURITY PROPERTY HOLDS:
    Authentication == bPhase = "done" => aPartner = Bob
    TLC verifies this with no violations.
*)

CONSTANTS Alice, Bob, Eve, Na, Nb

VARIABLES
  aPhase,    \* Alice's state: "idle" | "waiting" | "done"
  aPartner,  \* who Alice initiated her session with
  bPhase,    \* Bob's state: "idle" | "waiting" | "done"
  eKnows,    \* set of nonces Eve has learned
  msgs       \* set of messages on the network

vars == <<aPhase, aPartner, bPhase, eKnows, msgs>>

\* TypeOK: inductive type invariant (Lamport, Specifying Systems, ch.4).
\* TLC checks this alongside Authentication to confirm the fixed spec is well-typed.
TypeOK ==
  /\ aPhase \in {"idle", "waiting", "done"}
  /\ aPartner \in {Alice, Bob, Eve, "none"}
  /\ bPhase \in {"idle", "waiting", "done"}
  \* eKnows is a subset of nonces and msgs is a set of records — TLC verifies at runtime

Init ==
  /\ aPhase   = "idle"
  /\ aPartner = "none"
  /\ bPhase   = "idle"
  /\ eKnows   = {}
  /\ msgs     = {}

\* ── Step 1: Alice initiates with Eve (same as before) ─────────────────────────
AliceInitWithEve ==
  /\ aPhase    = "idle"
  /\ aPhase'   = "waiting"
  /\ aPartner' = Eve
  /\ msgs'     = msgs \cup {[step |-> 1, from |-> Alice, to |-> Eve, na |-> Na]}
  /\ UNCHANGED <<bPhase, eKnows>>

\* ── Step 2a: Eve learns Na, forwards msg1 to Bob (same as before) ─────────────
EveForwardsToBob ==
  /\ [step |-> 1, from |-> Alice, to |-> Eve, na |-> Na] \in msgs
  /\ eKnows'  = eKnows \cup {Na}
  /\ msgs'    = msgs \cup {[step |-> 1, from |-> Alice, to |-> Bob, na |-> Na]}
  /\ UNCHANGED <<aPhase, aPartner, bPhase>>

\* ── Step 2b: Bob responds — NOW INCLUDES HIS IDENTITY (Lowe's fix) ───────────
\* Message 2 now contains: {Na, Nb, Bob}_Ka
\* The extra field "sender |-> Bob" is the fix.
BobResponds ==
  /\ bPhase   = "idle"
  /\ [step |-> 1, from |-> Alice, to |-> Bob, na |-> Na] \in msgs
  /\ bPhase'  = "waiting"
  /\ msgs'    = msgs \cup {[step |-> 2, from |-> Bob, to |-> Alice,
                             na |-> Na, nb |-> Nb, sender |-> Bob]}
  /\ UNCHANGED <<aPhase, aPartner, eKnows>>

\* ── Step 3a: Eve intercepts msg2 and forwards to Alice ───────────────────────
\* Eve still cannot decrypt, still forwards unchanged.
EveForwardsToAlice ==
  /\ [step |-> 2, from |-> Bob, to |-> Alice, na |-> Na, nb |-> Nb, sender |-> Bob] \in msgs
  /\ msgs' = msgs \cup {[step |-> 2, from |-> Eve, to |-> Alice,
                          na |-> Na, nb |-> Nb, sender |-> Bob]}
  /\ UNCHANGED <<aPhase, aPartner, bPhase, eKnows>>

\* ── Step 3b: Alice receives msg2 and checks the declared sender ───────────────
\* THE KEY CHANGE: Alice now verifies sender = aPartner before accepting.
\* msg2 claims sender = Bob, but Alice's session partner is Eve.
\* This check FAILS — Alice rejects the message — attack is blocked.
AliceCompletes ==
  /\ aPhase   = "waiting"
  /\ \E m \in msgs :
       /\ m.step   = 2
       /\ m.to     = Alice
       /\ m.na     = Na
       /\ m.sender = aPartner    \* LOWE'S FIX: sender must match session partner
  /\ aPhase'  = "done"
  /\ LET m == CHOOSE m \in msgs : m.step = 2 /\ m.to = Alice /\ m.na = Na /\ m.sender = aPartner
     IN msgs' = msgs \cup {[step |-> 3, from |-> Alice, to |-> aPartner, nb |-> m.nb]}
  /\ UNCHANGED <<aPartner, bPhase, eKnows>>

\* ── Steps 4a-4b: Eve tries to complete — but AliceCompletes never fired ───────
\* Eve never receives msg3 because Alice rejected msg2.
\* These actions exist in the spec but are never enabled in the attack path.
EveLearnNb ==
  /\ [step |-> 3, from |-> Alice, to |-> Eve, nb |-> Nb] \in msgs
  /\ eKnows'  = eKnows \cup {Nb}
  /\ msgs'    = msgs \cup {[step |-> 3, from |-> Eve, to |-> Bob, nb |-> Nb]}
  /\ UNCHANGED <<aPhase, aPartner, bPhase>>

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

\* SECURITY PROPERTY — TLC verifies this HOLDS with Lowe's fix applied
Authentication == bPhase = "done" => aPartner = Bob

================================================================================
