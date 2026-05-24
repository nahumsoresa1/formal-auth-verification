# CE 365 Final Project Report
## Agentic System for Robust Cyber-Security

**Northwestern University — CE 365: Intro. to Formal Spec. and Verification**
**Prof. Hai Zhou**

**Team Members:** Miguel Hernandez · Nahum Soresa
**GitHub:** https://github.com/nahumsoresa1/formal-auth-verification

---

## 1. Project Overview

We built an agentic system that automatically verifies security protocols using TLA+ and the TLC model checker. The system targets a fundamental problem in software security: developers design authentication protocols without formal guarantees of correctness, and vulnerabilities only emerge after deployment — sometimes years later.

Our agent addresses this. A user selects a protocol. The agent runs TLC to exhaustively explore every possible system state, finds attacks if they exist, uses a local language model (Ollama) to explain the attack in plain English, and then either verifies a pre-written fixed spec or — in generative mode — has the LLM write the fixed spec from scratch and loops until TLC verifies it.

The entire loop runs autonomously without human intervention at each step.

### What makes this different from testing

TLC does not sample inputs — it exhaustively explores **every reachable state** of the system. When TLC says an invariant holds, it is a mathematical proof that no execution, however unlikely or adversarial, can violate the property. When TLC finds a counterexample, it is a guaranteed real attack, not a false positive. This is the core value of formal verification over conventional security testing.

---

## 2. System Architecture

The system has two operating modes built on a shared verification core:

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   User selects a protocol                                    │
│                          │                                   │
│                          ▼                                   │
│           ┌──────────────────────────┐                       │
│           │   Python Orchestrator    │                       │
│           │   agent/main.py          │                       │
│           └─────────────┬────────────┘                       │
│                         │                                    │
│              ┌──────────┴──────────┐                         │
│              │                     │                         │
│              ▼                     ▼                         │
│   ┌─────────────────┐   ┌─────────────────────┐             │
│   │  TLC Model      │   │  LLM (Ollama)        │             │
│   │  Checker        │   │  llama3.1 local      │             │
│   │  specs/*.tla    │   │  llm_client.py       │             │
│   └────────┬────────┘   └──────────┬──────────┘             │
│            │                       │                         │
│     ┌──────┴──────┐                │                         │
│     │             │                │                         │
│   PASS          FAIL               │                         │
│     │             │                │                         │
│     ▼             └──────────────► │                         │
│  VERIFIED      Attack trace   Explains attack                │
│  SECURE        extracted      in plain English               │
│                                    │                         │
│              Classic mode          │  Generative mode        │
│              ──────────────        │  ──────────────         │
│              Run pre-written ◄─────┤  LLM writes fix        │
│              fixed spec            │  TLC re-verifies        │
│              TLC verifies          │  Loop until hold        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Python Orchestrator (`agent/main.py`)**
Manages the full loop: loads specs, invokes TLC, parses output, calls the LLM, and produces the final summary. Also implements the generative loop (`--generate`): the LLM writes a fixed spec, TLC verifies it, and the loop retries (with error feedback) until the invariant holds or the iteration limit is reached.

**TLC Model Checker (`agent/tlc_runner.py`)**
Wraps the `tla2tools.jar` binary as a subprocess. Auto-detects the jar across VS Code extension updates. Parses violation output and extracts counterexample traces for the LLM.

**LLM Interface (`agent/llm_client.py`)**
Sends the spec and TLC trace to a locally running Ollama instance (no API key, no cost). The LLM identifies the attack type, explains each step in plain English, and — in generative mode — writes a corrected TLA+ spec. A multi-pass sanitizer auto-corrects the most common LLM TLA+ syntax errors before the spec is written to disk.

---

## 3. Protocols Verified

### 3.1 Insecure Login — Replay Attack

**Protocol:** User sends username and password in plaintext. Server accepts and logs the user in.

**Attacker model:** Passive attacker who can intercept messages and replay them.

**TLA+ spec:** `specs/InsecureLogin.tla`
- State variables: `state`, `network`, `loggedIn`, `attackerKnows`
- Actions: `SendCredentials`, `AttackerIntercept`, `LoginSuccess`, `AttackerReplay`
- Invariant: `NoReplay` — if logged in, the attacker must not know the credentials

**TLC result:** ❌ Invariant violated — 6 states explored

**Counterexample (4 steps):**
```
State 1:  state="start",         loggedIn=FALSE, attackerKnows=FALSE
State 2:  state="sent",          credentials on network, attackerKnows=FALSE
State 3:  state="sent",          attackerKnows=TRUE   ← attacker intercepts
State 4:  state="authenticated", loggedIn=TRUE, attackerKnows=TRUE
          *** NoReplay VIOLATED ***
```

**What TLC proved:** In every possible execution of this protocol where the attacker is present, the attacker can authenticate as the legitimate user. The vulnerability is not just exploitable — it is unavoidable.

---

### 3.2 Secure Login — Nonce-Based Challenge-Response

**Protocol:** Server issues a fresh nonce (challenge) before accepting credentials. Client must include the current nonce in their response. Once the server accepts a nonce, it is permanently marked as used.

**TLA+ spec:** `specs/SecureLogin.tla`
- Added variables: `phase`, `nonceUsed`, `authenticatedBy`
- Key fix: `ServerVerify` requires `~nonceUsed` before accepting credentials, then sets `nonceUsed = TRUE`
- Invariant: `NoReplay` — if logged in, `authenticatedBy = "user"`

**TLC result:** ✅ Invariant holds — 7 states explored, no violations

**Why it works:** `AttackerReplay` requires `~nonceUsed`, but `nonceUsed = TRUE` as soon as the session completes. TLC proves that no state exists where the attacker can successfully replay captured credentials after the nonce is spent.

---

### 3.3 Needham-Schroeder Public Key Protocol — MITM Attack

**Background:** Designed in 1978 by Needham and Schroeder. Believed to be a sound mutual authentication protocol for 17 years. In 1995, Gavin Lowe found a man-in-the-middle attack using automated model checking — a landmark result in formal verification of security protocols.

**Protocol:**
```
1.  A → B : {A, Na}_Kb       Alice sends identity + nonce, encrypted for Bob
2.  B → A : {Na, Nb}_Ka      Bob responds with both nonces, encrypted for Alice
3.  A → B : {Nb}_Kb          Alice confirms by returning Bob's nonce
```

**TLA+ spec:** `specs/NeedhamSchroeder.tla`
- Principals: Alice, Bob, Eve (attacker)
- Nonces: Na (from Alice), Nb (from Bob)
- Actions model each message send, Eve's interceptions, and Eve's forwards
- Invariant: `Authentication` — if Bob completed the protocol, Alice must have initiated with Bob

**TLC result:** ❌ Invariant violated — 17 states explored

**The attack (8-step counterexample):**
```
State 1:  Initial — all parties idle
State 2:  Alice initiates with Eve: sends {Alice, Na} encrypted for Eve
State 3:  Eve decrypts (it's for her), learns Na, forwards to Bob as if from Alice
State 4:  Bob responds to Alice: sends {Na, Nb} encrypted for Alice
State 5:  Eve intercepts and forwards to Alice (cannot decrypt — it's for Alice)
State 6:  Alice sees her own Na, trusts the message, sends {Nb} encrypted for Eve
State 7:  Eve decrypts (it's for her), learns Nb, forwards to Bob encrypted for Bob
State 8:  Bob receives {Nb}, completes protocol — believes he authenticated with Alice
          *** Authentication VIOLATED: bPhase="done", aPartner=Eve (not Bob) ***
```

**What TLC proved:** Bob believes he authenticated with Alice. He did not — Eve was the man in the middle throughout. Alice never initiated a session with Bob. The attack is not a flaw in the encryption — it exploits the fact that message 2 does not declare who sent it.

---

### 3.4 Needham-Schroeder-Lowe — Fixed Protocol

**Lowe's fix (1995):** Add the responder's identity to message 2:
```
2'.  B → A : {Na, Nb, B}_Ka     Bob now includes his own identity ← the fix
```

**Why it works:** When Alice receives message 2', she sees Bob's identity inside the message. Alice checks: does the declared sender match her session partner? She initiated with Eve, so her session partner is Eve — not Bob. The message is rejected. Eve's forwarding chain breaks at step 6. Bob never receives message 3 and never completes the protocol.

**TLA+ spec:** `specs/NeedhamSchroederFixed.tla`
- Single change: `BobResponds` adds `sender |-> Bob` to message 2
- `AliceCompletes` adds `m.sender = aPartner` check before accepting

**TLC result:** ✅ Invariant holds — 9 states explored, no violations

---

### 3.5 OAuth 2.0 Authorization Code Flow — Code Interception Attack

**Protocol:** Standard OAuth 2.0 authorization code grant. The authorization server issues a short-lived code via a redirect URL. The client exchanges the code for an access token.

**Attacker model:** Network attacker who can intercept the redirect URL and attempt to exchange the stolen code for a token independently.

**TLA+ spec:** `specs/OAuth2.tla`
- State variables: `phase`, `codeOnWire`, `codeUsed`, `attackerHasCode`, `tokenHolder`
- Actions: `AuthServerIssueCode`, `AttackerInterceptCode`, `ClientExchangeCode`, `AttackerExchangeCode`
- Invariant: `OnlyClientGetsToken` — `tokenHolder` can only ever be `"client"` or `"none"`

**TLC result:** ❌ Invariant violated — 9 states explored

**Counterexample (4 steps):**
```
State 1:  phase="idle",        codeOnWire=FALSE, tokenHolder="none"
State 2:  phase="code_issued", codeOnWire=TRUE               ← auth server issues code
State 3:  attackerHasCode=TRUE                               ← attacker intercepts redirect
State 4:  tokenHolder="attacker"                             ← attacker exchanges stolen code
          *** OnlyClientGetsToken VIOLATED ***
```

**What TLC proved:** Without an additional binding mechanism, any attacker who can observe the redirect URL can exchange the code for a token before the legitimate client does.

---

### 3.6 OAuth 2.0 with PKCE — Fixed Protocol

**Fix — PKCE (RFC 7636):** The client generates a secret `code_verifier` before the flow begins. It sends a `code_challenge` (hash of the verifier) to the authorization server up front. When exchanging the code for a token, the client must prove it knows the verifier. An attacker who only intercepts the redirect URL never learns the verifier.

**TLA+ spec:** `specs/OAuth2Fixed.tla`
- Added `CONSTANT ClientVerifier` — the client's secret, known only to the client
- Added variable `attackerKnowsVerifier` — initialized `FALSE`, never set `TRUE`
- `AuthServerIssueCode` stores `storedChallenge := ClientVerifier`
- `ClientExchangeCode` requires `storedChallenge = ClientVerifier` (the client can satisfy this)
- `AttackerExchangeCode` requires `attackerKnowsVerifier = TRUE` (permanently `FALSE` — action is unreachable)

**TLC result:** ✅ Invariant holds — 8 states explored, no violations

**Why it works:** `AttackerExchangeCode` is guarded by `attackerKnowsVerifier = TRUE`. Because `attackerKnowsVerifier` is never set to `TRUE` anywhere in the spec, TLC proves that action is unreachable in any execution — the attacker can never exchange the stolen code.

---

## 4. Verification Results Summary

| Protocol | Invariant | TLC Result | States | Attack |
|---|---|---|---|---|
| `InsecureLogin` | `NoReplay` | ❌ Violated | 6 | Replay — attacker reuses captured credentials |
| `SecureLogin` | `NoReplay` | ✅ Verified | 7 | Nonce prevents replay |
| `NeedhamSchroeder` | `Authentication` | ❌ Violated | 17 | MITM — Eve impersonates Alice to Bob |
| `NeedhamSchroederFixed` | `Authentication` | ✅ Verified | 9 | Identity in msg2 blocks the attack |
| `OAuth2` | `OnlyClientGetsToken` | ❌ Violated | 9 | Code interception — attacker steals redirect code |
| `OAuth2Fixed` | `OnlyClientGetsToken` | ✅ Verified | 8 | PKCE (RFC 7636) blocks code exchange |

---

## 5. Agent Demo

The full pipeline runs from the command line with no manual steps between TLC and the LLM.

### Classic mode — pre-written fixes
```bash
python3 agent/main.py --demo insecure   # replay attack on login protocol
python3 agent/main.py --demo ns         # Needham-Schroeder MITM attack (1978/1995)
python3 agent/main.py --demo oauth      # OAuth 2.0 code interception + PKCE fix
```

Each classic demo:
1. Runs TLC on the insecure spec — prints the counterexample trace
2. Sends the trace to Ollama — LLM explains the attack in plain English
3. Runs TLC on the fixed spec — confirms the fix is verified secure
4. Prints a comparison summary

### Generative mode — LLM writes the fix, TLC re-verifies
```bash
python3 agent/main.py --demo oauth --generate     # LLM generates PKCE fix live
python3 agent/main.py --spec MyProto --generate   # generative loop on any spec
```

The generative loop:
1. LLM explains the attack and produces a one-line summary
2. LLM generates a complete fixed TLA+ spec from scratch
3. A multi-pass sanitizer corrects common LLM syntax errors before TLC sees the file
4. TLC verifies the generated spec — if still violated, the counterexample is fed back to the LLM
5. Repeat up to 3 iterations; on each retry the error message is included in the prompt

For OAuth2, the loop also validates that the generated fix implements the correct PKCE pattern (`attackerKnowsVerifier`) rather than a vacuous alternative that happens to pass TLC.

---

## 6. Test Suite

The project includes 22 automated tests covering every critical component:

```bash
python3 tests/test_agent.py
```

| Test Class | Tests | What is covered |
|---|---|---|
| `TestTLCJar` | 1 | TLC jar is findable after VS Code updates |
| `TestTLCRunner` | 4 | Violation detection, state counting, graceful error handling |
| `TestSecureLogin` | 3 | NoReplay holds, contrast with insecure version |
| `TestNeedhamSchroeder` | 4 | MITM attack found, Lowe's fix verified, contrast |
| `TestOAuth2` | 5 | Code interception found, PKCE fix verified, PKCE pattern validated |
| `TestOllamaConnection` | 2 | Ollama reachable, LLM returns meaningful analysis |
| `TestGenerativeLoop` | 2 | `generate_fix()` returns valid TLA+, `summarize_attack()` stays short |
| `TestFullLoop` | 1 | End-to-end: TLC → LLM → correct attack identification |

All 22 tests pass.

---

## 7. Technical Stack

| Component | Technology | Notes |
|---|---|---|
| Formal specification | TLA+ | 6 specs — 3 insecure / 3 secure |
| Model checking | TLC (tla2tools.jar) | Bundled with VS Code TLA+ extension |
| Agent orchestration | Python 3 | Subprocess + output parsing |
| LLM | Ollama / llama3.1 | Runs locally, no API cost |
| TLA+ sanitizer | Python regex | Auto-corrects 11 classes of LLM syntax errors |
| Version control | Git / GitHub | `nahumsoresa1/formal-auth-verification` |

---

## 8. Conclusions

This project demonstrates that formal verification can be made accessible through automation. The key results are:

1. **TLC finds real attacks automatically.** For all three insecure protocols — login replay, the 17-year-old Needham-Schroeder flaw, and OAuth 2.0 code interception — TLC produces exact counterexample traces in under one second with no manual guidance.

2. **TLC proves fixes are correct.** Once the nonce-based login, Lowe's NS fix, and PKCE are applied, TLC exhaustively verifies that no attack path exists — not just that we did not find one, but that none can exist.

3. **The generative loop closes the loop end-to-end.** In Level 2 mode, the LLM writes the fix without a pre-written spec. The loop retries with specific error feedback until TLC verifies the invariant holds. This shows that the agent can reason about both the attack and the fix, not just explain it.

The agentic loop — run TLC, explain the attack, generate or verify the fix — removes the expert bottleneck from protocol verification. A developer with no background in formal methods can run the agent, read the LLM explanation, and understand exactly what is wrong and why the fix works.

---

## 9. Division of Work

| Task | Owner |
|---|---|
| `InsecureLogin.tla` + `SecureLogin.tla` | Miguel |
| `NeedhamSchroeder.tla` + `NeedhamSchroederFixed.tla` | Nahum |
| `OAuth2.tla` + `OAuth2Fixed.tla` | Miguel |
| Python agent orchestration (`main.py`, `tlc_runner.py`) | Miguel |
| Ollama LLM integration (`llm_client.py`, `prompts.py`) | Miguel |
| Generative loop + TLA+ sanitizer | Miguel |
| Test suite (`tests/test_agent.py`) | Miguel + Nahum |
| Final report and documentation | Both |
