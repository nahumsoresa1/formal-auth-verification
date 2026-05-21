MODULE InsecureLoginDemo

(* Constants *)
CONSTANT username = "alice"
CONSTANT password = "secret"

(* Variables *)
VARIABLE
  clientState = {
    userSent: {TRUE, FALSE},
    passSent: {TRUE, FALSE},
    authenticated: {TRUE, FALSE}
  },
  serverState = {
    credReceived: {TRUE, FALSE},
    accessGranted: {TRUE, FALSE}
  },
  attackerState = {
    intercepted: {username: "" , password: ""},
    replayed: {username: "", password: ""}
  }

(* Init *)
Init ==
  clientState.userSent = FALSE
/\ serverState.credReceived = FALSE
/\ attackerState.intercepted.username = ""
/\ attackerState.intercepted.password = ""

(* Next *)
Next == 
  (\E i \in {client, server, attacker} : 
    (VARS clientState, serverState, attackerState;
      (
        (\* Client initiates login request *\)      
          clientState.userSent' = TRUE
          /\ clientState.passSent' = FALSE
          /\ serverState.credReceived' = FALSE

        \/ (\* Server receives login credentials and grants access *) 
          serverState.credReceived' = TRUE
          /\ serverState.accessGranted' = TRUE
          
        \/ (\* Attacker intercepts message *\)  
          attackerState.intercepted.username' = clientState.userSent
          /\ attackerState.intercepted.password' = clientState.passSent

        \/ (\* Attacker replays intercepted credentials *\) 
          attackerState.replayed.username' = serverState.credReceived
          /\ attackerState.replayed.password' = serverState.accessGranted

        \/ (\* User authenticates successfully *)  
          clientState.authenticated' = TRUE
      )
    ))


(* Security Property *)
SecurityProperty == 
  \A t: Temporal \* All states in the temporal evolution of the system:
    (clientState.authenticated[t] = TRUE) => (attackerState.intercepted.username[t] = "" /\ attackerState.intercepted.password[t] = "")

Spec == Init /\ [][Next]_vars