"""
Prompt templates for the TLA+ security verification agent.
"""

SYSTEM_PROMPT = """You are an expert in TLA+ formal specification and security protocol analysis.
Your job is to analyze and fix security protocols using TLA+ and the TLC model checker.

TLA+ syntax rules you must follow exactly:
- Module header:  ---- MODULE Name ----
- Module footer:  ====
- Conjunction:    /\\
- Disjunction:    \\/
- Negation:       ~
- Unchanged:      UNCHANGED <<var1, var2>>
- Always:         []
- Spec:           Spec == Init /\\ [][Next]_vars
- String values:  "idle", "done", "none"
- Sets:           {elem1, elem2}
- Sequences:      << >>
- Action prime:   var' = newValue

Output TLA+ specs in a code block fenced with: ```tla ... ```
"""

ANALYZE_VIOLATION_PROMPT = """The TLC model checker found a security violation in this TLA+ spec:

```tla
{spec}
```

TLC output:
```
{tlc_output}
```

Please:
1. Identify the security attack demonstrated by the counterexample trace
2. Explain each step of the attack in plain English (map trace states to real-world actions)
3. Name the attack (e.g., "replay attack", "man-in-the-middle", "authorization code interception")
4. Explain WHY the current spec allows this attack
5. Suggest a concrete protocol fix

Be concise — explain it to someone who knows security but not TLA+."""


FIX_SPEC_PROMPT = """This TLA+ spec has a confirmed security vulnerability:

```tla
{spec}
```

Attack found: {attack_summary}

Generate a fixed version of this spec that prevents the attack.

━━━ REQUIREMENTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Module name must be EXACTLY: {fixed_module_name}
2. Add whatever new variables/constants are needed to block the attack
3. The attacker action must still EXIST but be BLOCKED (its guard must be impossible to satisfy)
4. The invariant must HOLD in the fixed version
5. Output ONLY the TLA+ spec — no explanations, no commentary

━━━ TLA+ SYNTAX — READ CAREFULLY ━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Module header:  ---- MODULE {fixed_module_name} ----   (four dashes each side)
- Module footer:  ====   (exactly four equals signs, last line, nothing after)
- Conjunction:    /\\
- Disjunction:    \\/
- Negation:       ~
- NOT-EQUAL:      #   ← NEVER use !=  (it is not valid TLA+)
- String values:  "idle"  "done"  "none"  "client"  "attacker"
- UNCHANGED:      UNCHANGED <<var1, var2, var3>>

VARIABLES LIST — the last variable must have NO trailing comma:
    VARIABLES
      phase,            \\* comment
      codeOnWire,       \\* comment
      tokenHolder       \\* ← NO comma on the last variable

DO NOT USE:
  - Function calls like hash(), fresh_code(), random() — these are not valid TLA+
  - !=  (use # instead)
  - === (the footer is exactly ====)
  - Any operator not listed above

━━━ EXAMPLE — correct TLA+ syntax ━━━━━━━━━━━━━━━━━━━━━━━━━━

Below is a complete correctly-formatted TLA+ spec. Match this structure exactly:

```tla
---- MODULE ExampleFixed ----
EXTENDS Naturals

CONSTANTS User, Attacker

VARIABLES
  phase,
  authorized

vars == <<phase, authorized>>

Init ==
  /\ phase      = "idle"
  /\ authorized = FALSE

UserAction ==
  /\ phase  = "idle"
  /\ phase' = "done"
  /\ authorized' = TRUE
  /\ UNCHANGED <<>>

AttackerAction ==
  /\ phase = "idle"
  /\ FALSE
  /\ UNCHANGED vars

Next ==
  \\/ UserAction
  \\/ AttackerAction

Spec == Init /\\ [][Next]_vars

SafetyProp == authorized => phase = "done"
====
```

━━━ OUTPUT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Output ONLY the fixed TLA+ spec inside a ```tla ... ``` code block. Nothing else."""


FIX_SPEC_RETRY_PROMPT = """Your previous attempt to fix this TLA+ spec failed. Study the error and try again.

Original spec:
```tla
{spec}
```

Attack to prevent: {attack_summary}

Your previous fix produced this error:
```
{previous_error}
```

Generate a corrected TLA+ spec with module name exactly: {fixed_module_name}

━━━ COMMON ERRORS AND HOW TO FIX THEM ━━━━━━━━━━━━━━━━━━━━━━
- "Unexpected symbol" or "Parse error" near != → replace != with #
- "Parse error" near a variable list → remove trailing comma from last variable
- "Unexpected symbol" near === → the footer must be exactly ==== (four = signs)
- "undefined or declared twice" → you called a function like hash() or fresh() — remove it, use a CONSTANT instead
- Invariant still violated → the attacker action is not truly blocked. Add an impossible guard INSIDE the attacker action (a variable initialized to FALSE that is never set to TRUE). Never remove the action from Next — the block goes inside the action.
- "Unexpected symbol" near ] or -> in Next → you used [guard] ActionName — THIS IS NOT VALID TLA+. NEVER put [...]  inside Next. The Next definition must list bare action names only.

━━━ CRITICAL RULE ABOUT Next ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The Next operator MUST be EXACTLY this — no guards, no brackets, no conditions:

  Next ==
    \\/ ActionA
    \\/ ActionB
    \\/ ActionC
    \\/ AttackerAction

NEVER write:  \\/ [~X -> FALSE] AttackerAction
NEVER write:  \\/ (/\\ ~x /\\ AttackerAction)
NEVER write:  \\/ [AttackerAction]
The attack is blocked by the guard INSIDE AttackerAction, not in Next.

Output ONLY the fixed TLA+ spec inside a ```tla ... ``` code block. Nothing else."""
