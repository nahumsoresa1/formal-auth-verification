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

STRICT REQUIREMENTS:
1. Module name must be exactly: {fixed_module_name}
2. Keep all the same variables but add whatever is needed to block the attack
3. The attacker actions must still exist but must be blocked by the fix
4. The invariant must HOLD in the fixed version
5. Follow TLA+ syntax exactly:
   - Module header: ---- MODULE {fixed_module_name} ----
   - Module footer: ====
   - Use /\\ for AND, \\/ for OR, ~ for NOT
   - UNCHANGED <<var1, var2>> for unchanged variables
   - Spec == Init /\\ [][Next]_vars

Common fixes:
- Replay attack → add a nonce: server issues fresh value, marks it used after verification
- MITM attack → add identity to messages: receiver verifies sender matches expected partner
- Code interception → add code_verifier: secret that was never transmitted

Output ONLY the fixed TLA+ spec in a ```tla ... ``` code block. Nothing else."""
