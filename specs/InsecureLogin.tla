------------------------------ MODULE InsecureLogin ------------------------------
EXTENDS Naturals, Sequences

(*
  Insecure Authentication Protocol
  ---------------------------------
  A user sends credentials (username + password) in plaintext over the network.
  An attacker can intercept the message and replay it to impersonate the user.

  Security property violated: NoReplay
    - An attacker who captures credentials can replay them and authenticate
      as the legitimate user without knowing the original password.
*)

CONSTANTS User, Attacker, Password

VARIABLES state, network, loggedIn, attackerKnows

vars == <<state, network, loggedIn, attackerKnows>>

Init ==
  /\ state = "start"
  /\ network = << >>
  /\ loggedIn = FALSE
  /\ attackerKnows = FALSE

\* User sends credentials in plaintext
SendCredentials ==
  /\ state = "start"
  /\ network' = Append(network, <<"user", Password>>)
  /\ state' = "sent"
  /\ UNCHANGED <<loggedIn, attackerKnows>>

\* Attacker intercepts the message and learns the password
AttackerIntercept ==
  /\ state = "sent"
  /\ Len(network) > 0
  /\ attackerKnows' = TRUE
  /\ UNCHANGED <<state, network, loggedIn>>

\* Server accepts credentials and logs the user in
LoginSuccess ==
  /\ state = "sent"
  /\ loggedIn' = TRUE
  /\ state' = "authenticated"
  /\ UNCHANGED <<network, attackerKnows>>

\* Attacker replays intercepted credentials to authenticate
AttackerReplay ==
  /\ attackerKnows = TRUE
  /\ state \in {"start", "sent"}
  /\ loggedIn' = TRUE
  /\ state' = "authenticated"
  /\ UNCHANGED <<network, attackerKnows>>

Next ==
  \/ SendCredentials
  \/ AttackerIntercept
  \/ LoginSuccess
  \/ AttackerReplay

Spec == Init /\ [][Next]_vars

\* SAFETY PROPERTY: loggedIn should only become TRUE via legitimate authentication
\* This is VIOLATED because AttackerReplay can set loggedIn = TRUE
NoReplay == loggedIn => (state = "authenticated" /\ ~attackerKnows)

\* Weaker property: the system can authenticate someone
CanAuthenticate == <>(loggedIn = TRUE)

=============================================================================
