---
name: elite-0day-researcher
description: Use when performing security research, vulnerability hunting, 0-day discovery, exploit development, code auditing, or penetration testing against source code or running systems. Triggers on any security assessment, bug bounty, red team, or vulnerability analysis task.
user-invocable: true
---

# Elite 0-Day & Exploit Researcher

A systematic methodology for discovering genuine, novel, exploitable vulnerabilities. Distilled from 88,636 real-world vulnerability cases (WooYun archive 2010-2016) and hardened against false-positive patterns observed in production assessments.

```
Core Principle:
  Vulnerability = Developer Assumption XOR Attacker Input -> Unexpected State

The art is finding where assumptions break.
Not where code runs. Not where PoCs execute.
Where ASSUMPTIONS FAIL.
```

---

## The Iron Law

**Every claimed vulnerability MUST: (1) demonstrate privilege escalation, trust boundary violation, or unauthorized state transition, (2) be validated dynamically against a running system in production-representative configuration, and (3) be verified as novel against known CVEs. A finding that fails ANY of these is not a reportable 0-day. No exceptions.**

---

## Phase 1: Attack Surface Inventory

Before hunting, map everything. Never sample. Never guess.

```
DO:
1. Enumerate ALL entry points:
   - HTTP endpoints (routes, handlers, API paths)
   - IPC channels (RPC, gRPC, message queues)
   - File inputs (config parsers, upload handlers, deserializers)
   - CLI arguments and environment variables
   - Protocol handlers (TLS, SAML, OAuth, custom)

2. For each entry point, record:
   - Authentication requirement (none / token / cert / session)
   - Authorization level (unauthenticated / user / admin / root)
   - Input validation present (type / regex / allowlist / none)
   - Data flow to sinks (SQL / command / file / crypto / network)

3. Map trust boundaries:
   - Where does privilege level change?
   - Where does data cross from untrusted to trusted?
   - Where do network boundaries exist?
   - What does each privilege level ALREADY grant?

OUTPUT: attack-surface.json with every entry point catalogued
```

### Trust Boundary Mapping

```
                    UNTRUSTED                    TRUSTED
                    ─────────                    ───────
Unauthenticated ──┬── Auth boundary ──┬── User level
                  │                   │
                  │                   ├── Operator level
                  │                   │
                  │                   └── Root/Admin level
                  │
                  └── Network boundary ── Internal services
                                          Cloud metadata
                                          Localhost

RULE: Vulnerabilities cross boundaries UPWARD or SIDEWAYS.
      Actions WITHIN a boundary at the SAME level = by-design.
```

---

## Phase 2: Vulnerability Pattern Library

### 2.1 The Five Questions (ask for EVERY code path)

```
Q1: Where does data come from?     (input source)
    GET/POST/Cookie/Header/File/IPC/Environment

Q2: Where does data go?            (sink)
    SQL query / OS command / file path / HTTP request /
    crypto operation / HTML output / deserialization

Q3: Where is data trusted?         (trust boundary crossing)
    Frontend→Backend / User→Admin / External→Internal

Q4: How is data transformed?       (processing)
    Filtered / escaped / validated / normalized / executed

Q5: What does the developer ASSUME? (the target)
    "This is always an integer"
    "This URL is always external"
    "This user can only access their own data"
    "This is always called after authentication"
    "Case doesn't matter" / "Case always matches"
```

### 2.2 High-Value Vulnerability Patterns

Ranked by real-world frequency and impact from 88,636 cases:

**SSRF (Server-Side Request Forgery)**
```
Pattern: User-controlled URL → server-side HTTP request
Kill shot: No private IP filtering on outbound requests

Hunt for:
- http.Get(userInput) / requests.get(url) with no IP validation
- URL validation that only checks syntax (url.Parse) not destination
- CRL fetchers, webhook dispatchers, JWKS URL configs, OAuth callbacks
- Redirect followers that escape URL allowlists

Signals (from error messages):
- "asn1: structure error" = connected, got non-expected response
- "connection refused" = port closed (port scan oracle)
- "timeout" = filtered (firewall oracle)
- Different error = different state = information leak
```

**Missing Auth / Broken Access Control**
```
Pattern: Endpoint registered outside auth middleware
Kill shot: Unauthenticated endpoint performs privileged operation

Hunt for:
- Handlers registered directly on mux (not through auth wrapper)
- Auth checks that don't return after failure (missing return!)
- Middleware ordering bugs (CORS before auth, logging before auth)
- IDOR: user ID from request used without ownership check
```

**Logic Bugs (highest creativity required)**
```
Pattern: Operation ordering violations
Kill shot: State mutation before validation

Hunt for:
- Resource consumed BEFORE permission check (use count, balance, quota)
- Validation on READ path but not WRITE path
- Normalization inconsistency (read lowercases, write doesn't)
- TOCTOU: check and use happen at different times
- Missing return after error response (Go pattern: respondError without return)

The normalization family:
- Case: user/TestUser vs user/testuser (different storage keys)
- Encoding: %2f vs / (path traversal through URL encoding)
- Unicode: different normalizations producing different keys
- Whitespace: trimmed on read, preserved on write
```

**Injection (the classics, still everywhere)**
```
SQL:  Parameters concatenated into queries (not parameterized)
CMD:  User input in exec/system/popen without shell escaping
Path: User input in file operations without traversal filtering
LDAP: User input in LDAP filters without escaping
Template: User input rendered in server-side templates

Bypass toolkit (from 27,732 real SQL injection cases):
- Space bypass: /**/ %09 %0a ()
- Keyword bypass: SeLeCt sel%00ect /*!select*/
- Quote bypass: 0x hex, char(), concat()
- WAF bypass: chunked encoding, parameter pollution, HPP
```

**Cryptographic Misuse**
```
Pattern: Crypto API used incorrectly
Kill shot: Predictable tokens, weak randomness, key reuse

Hunt for:
- math/rand instead of crypto/rand for security tokens
- Hardcoded keys/IVs/salts
- ECB mode usage
- HMAC comparison with == instead of constant-time compare
- Certificate validation disabled (InsecureSkipVerify)
```

### 2.3 The "Missing Return" Pattern (Go-specific, high-value)

```go
// VULNERABLE: execution continues after error response
if core.Sealed() {
    respondError(w, http.StatusBadRequest, err)
    // Missing return! Falls through to privileged operation
}
doPrivilegedOperation()  // Executes even when sealed

// FIXED:
if core.Sealed() {
    respondError(w, http.StatusBadRequest, err)
    return  // <-- this one line is the entire fix
}
```

Hunt for this pattern in EVERY error-handling block in HTTP handlers. `grep -n "respondError\|writeError\|sendError" | grep -v "return"` is your friend.

---

## Phase 3: Systematic Exploitation Process

### 3.1 Attack Tree Construction

For each potential finding, build a structured attack tree:

```
Root: [Vulnerability hypothesis]
├── Precondition 1: [What must be true?]
│   ├── Realistic? [Y/N + evidence]
│   └── Who has this access? [role]
├── Precondition 2: [What configuration required?]
│   ├── Default? [Y/N]
│   └── Common in production? [Y/N + evidence]
├── Attack step 1: [Specific action]
│   └── Evidence: [code path, line numbers]
├── Attack step 2: [Specific action]
│   └── Evidence: [code path, line numbers]
└── Impact: [What does attacker gain?]
    └── Exceeds starting privilege? [Y/N]  ← CRITICAL CHECK
```

### 3.2 PROXIMITY Tracking

Track how close you are to successful exploitation:

```
PROXIMITY levels:
1. Found potential sink                    [20%]
2. Confirmed input reaches sink           [40%]
3. Bypassed one layer of validation       [60%]
4. Payload constructed, blocked by X      [80%]
5. PoC executes, impact demonstrated      [100%]

Log PROXIMITY after every attempt.
If PROXIMITY unchanged after 3 attempts → try different vector.
If PROXIMITY improving → continue this path.
After 5 failed attempts on one branch → move to next branch.
```

### 3.3 Hypothesis-Driven Testing

```
For each hypothesis:
1. STATE it clearly: "Function X is vulnerable to Y because Z"
2. PREDICT the outcome: "If I send input A, I expect behavior B"
3. TEST it: Build and run the PoC
4. RECORD result: Confirmed / Disproven / Partial (update PROXIMITY)
5. LEARN: What does this tell us about the next hypothesis?

Maintain:
- hypotheses.json: Active hypotheses with status
- disproven.json: Failed hypotheses (prevents re-testing)
- attack-paths.json: All paths attempted with results
```

---

## Phase 4: PoC Construction

### 4.1 PoC Requirements

Every PoC MUST:
```
1. Be HARMLESS — demonstrate the vulnerability without causing damage
2. Be REPRODUCIBLE — include exact commands, not pseudocode
3. Be MINIMAL — shortest path to demonstrate the issue
4. Show IMPACT — what does the attacker gain?
5. Show PRIVILEGE BOUNDARY — prove the attacker crosses a trust boundary
6. Work against DEFAULT or COMMON configuration
   (not against a test harness you built)
```

### 4.2 PoC Template

```bash
#!/bin/bash
# PoC: [Vulnerability Title]
# Severity: [LOW|MEDIUM|HIGH|CRITICAL]
# Preconditions: [List every requirement]
# Attacker privilege: [unauthenticated|user|operator|admin]
# Impact: [What is gained beyond starting privilege]

set -euo pipefail

TARGET="${1:-http://127.0.0.1:8200}"
TOKEN="${2:-}"  # Only if auth required — document WHY this token level

echo "[*] Step 1: [Description]"
RESULT=$(curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/endpoint")

echo "[*] Step 2: [Description]"
# ... exploit steps ...

echo "[*] Result: [What was achieved]"
echo "[*] This demonstrates: [Trust boundary crossed]"

# VALIDATION: Prove this wouldn't work without the vulnerability
echo "[*] Control test: [Show that fix would prevent this]"
```

---

## Phase 5: Mandatory Dynamic Validation (HARD GATE)

**No finding is accepted without dynamic proof against a running system. This is not optional. Static analysis finds candidates — dynamic validation makes them real.**

```
MANDATORY REQUIREMENTS:

STEP 1 — ENVIRONMENT SETUP:
  Set up the target in PRODUCTION-REPRESENTATIVE configuration.
  NOT dev mode. NOT debug mode. NOT single-node-test-mode.

  If you MUST use dev mode: every finding that depends on a dev-mode-only
  feature (e.g., raw storage endpoint, hardcoded root token, disabled auth)
  gets tagged as DEV-MODE-DEPENDENT and severity is capped at LOW.

  Document the exact configuration used:
  - Version and commit hash
  - Configuration flags that differ from defaults
  - Auth methods enabled
  - Storage backend

STEP 2 — EXECUTE EACH PoC:
  For EVERY finding, run the PoC against the live system.
  Record the EXACT output (not a summary, not "it worked").

  Capture:
  - HTTP response code and body
  - Error messages (verbatim)
  - State changes (before and after)
  - Timing information (for timing oracles)

STEP 3 — VALIDATE PREDICTED BEHAVIOR:
  Does the actual output match the PREDICTED behavior from static analysis?
  - YES → PASS (proceed)
  - PARTIALLY → document what differs, assess if it changes severity
  - NO → FAIL (finding is theoretical, not confirmed)

STEP 4 — CONTROL TEST (MANDATORY):
  Apply the suggested fix (or simulate it) and re-run the PoC.
  - Does the fix PREVENT the vulnerability? → Fix confirmed
  - Does the fix NOT break normal functionality? → Fix is safe
  - If you can't run a control test, document WHY and flag the finding
    as UNCONTROLLED

STEP 5 — ERROR ORACLE ANALYSIS (for blind/indirect vulns):
  When the vulnerability is blind (SSRF, timing, etc.):
  - Send the exploit input → record error/response
  - Send a benign input → record error/response
  - Send to a known-closed port → record error/response
  - DIFFERENT responses = information oracle confirmed
  - IDENTICAL responses = no oracle, finding may be theoretical

STEP 6 — RECORD RESULT:
  For each finding:
    dynamic_status: CONFIRMED | PARTIAL | FAILED | DEV-MODE-DEPENDENT
    evidence: [exact output captured]
    control_test: PASS | FAIL | NOT_RUN (with reason)

HARD STOP:
  If dynamic_status = FAILED → finding is REJECTED.
  Do not report findings that cannot be demonstrated dynamically.
  Do not report findings as "likely exploitable" or "theoretically possible."
  If it doesn't work against a running system, it doesn't ship.

EXCEPTION:
  Race conditions and timing-dependent bugs that are demonstrably real
  in code but difficult to trigger reliably may be reported as CONFIRMED
  (TIMING-DEPENDENT) with the static evidence + best dynamic attempt.
  These must still have at least one successful dynamic trigger or a
  clear explanation of why the timing window is realistic.
```

### Error Oracle Quick Reference

```
For SSRF / blind network vulnerabilities:

Response                          → Meaning
─────────────────────────────────────────────────────────
"asn1: structure error: tags..."  → Connected, got non-CRL data (port open)
"connection refused"              → Port closed
"i/o timeout"                     → Port filtered / host unreachable
"no such host"                    → DNS resolution failed
200 OK with content              → Full SSRF (jackpot)
Different response times          → Timing oracle

For auth / logic bugs:
─────────────────────────────────────────────────────────
204 No Content on write           → Action succeeded (check if it should have)
403 Forbidden                     → Auth check worked (expected for control test)
200 OK when expecting 403         → Auth bypass confirmed
Old credentials still work        → Password update didn't take effect
New credentials rejected          → State mutation bug confirmed
```

---

## Phase 6: Novelty Verification

**CRITICAL: Before claiming any finding is a 0-day, verify novelty. Only dynamically CONFIRMED findings (Phase 5) reach this stage.**

```
For each finding:

CHECK 1 — CVE Database:
  Search for CVEs matching:
  - Same component (file, module, endpoint)
  - Same vulnerability class (SSRF, auth bypass, etc.)
  - Same project AND its upstream/parent (forks inherit CVEs)
  Result: MATCH / NO MATCH

CHECK 2 — Project Advisories:
  Search the project's:
  - CHANGELOG / release notes
  - Security advisories (SECURITY.md, GitHub advisories)
  - Git log for the affected file (look for fix commits)
  Result: MATCH / NO MATCH

CHECK 3 — Variant Analysis (if CHECK 1 or 2 matched):
  Classify relationship:
  - DUPLICATE: Same vuln, same code path → NOT a 0-day
  - INCOMPLETE FIX: Same root cause, unfixed code path → Reportable as variant
  - INDEPENDENT: Same component, different vuln class → Novel finding

CHECK 4 — Upstream Inheritance (for forks):
  - Has the fork backported the parent's fix?
  - PATCHED → not reportable
  - UNPATCHED → reportable as "known unpatched" (not 0-day)
  - PARTIAL → analyze what remains unfixed

OUTPUT: Tag each finding as NOVEL / VARIANT / KNOWN
```

---

## Phase 7: Severity Assessment

### Real-World Severity Matrix

```
                    │ Unauthenticated │ Auth (user) │ Auth (admin) │ Root/Super
────────────────────┼─────────────────┼─────────────┼──────────────┼───────────
Remote Code Exec    │   CRITICAL      │   HIGH      │   MEDIUM     │ BY-DESIGN
Data Breach         │   CRITICAL      │   HIGH      │   MEDIUM     │ BY-DESIGN
Auth Bypass         │   CRITICAL      │   HIGH      │   LOW        │ N/A
Privilege Escalation│   CRITICAL      │   HIGH      │   MEDIUM     │ BY-DESIGN
SSRF (blind)        │   HIGH          │   MEDIUM    │   LOW        │ BY-DESIGN
Info Disclosure     │   MEDIUM        │   LOW       │   INFORMATIONAL│ BY-DESIGN
DoS                 │   MEDIUM        │   LOW       │   LOW        │ BY-DESIGN
Logic Bug           │   Depends on impact and boundary crossed
```

**Key rule:** If the required privilege level already grants the demonstrated capability through normal/documented means, severity = BY-DESIGN regardless of the code path used.

---

## Anti-Patterns: What NOT to Report

These are NOT vulnerabilities. Reporting them destroys credibility.

```
1. PRIVILEGE TAUTOLOGY
   "Root/admin can perform privileged operations"
   → That's what root/admin means.

2. ALGORITHM PROPERTIES
   "Same cryptographic key produces same output"
   → That's how math works (RFC 6238, etc.).

3. SPECIFICATION-REQUIRED BEHAVIOR
   "Discovery endpoint is unauthenticated"
   → RFC 8414 requires this.

4. FEATURES WORKING AS NAMED
   "sign-verbatim endpoint signs without restrictions"
   → Read the feature's own documentation.

5. TEST-HARNESS CIRCULARITY
   "Exploit works with the policy I created in my setup script"
   → You proved your test setup is powerful, not that the system is vulnerable.

6. KNOWN CVEs REPACKAGED
   "I found [known issue] and it's a 0-day"
   → Check CVE databases before claiming novelty.

7. CONFIGURATION WEAKNESSES
   "Dev mode has weaker security than production"
   → That's what dev mode is for.
```

---

## Reporting Template

```markdown
## [Finding Title]

**Severity:** [CRITICAL|HIGH|MEDIUM|LOW]
**Novelty:** [NOVEL | VARIANT of CVE-XXXX-XXXXX]
**Dynamic Validation:** CONFIRMED | PARTIAL | DEV-MODE-DEPENDENT
**Attack Complexity:** [LOW|MEDIUM|HIGH]
**Required Privilege:** [None|User|Operator|Admin]

**File:** `path/to/file.go:line_number`

### Description
[2-3 sentences: what is the vulnerability, why does it exist,
what assumption does it violate]

### Attack Flow
[ASCII diagram showing attacker → system → impact]

### Reproduction
[Exact commands to reproduce, with expected output]

### Dynamic Evidence
[Verbatim output from running PoC against live system]
[Include: response codes, error messages, state changes]

### Control Test
[Evidence that the suggested fix prevents the vulnerability]

### Impact
[What does the attacker gain BEYOND their starting privilege level?]

### Suggested Fix
[Specific code change, not generic advice]
```

---

## Quick Reference: Hunt Checklist

```
DISCOVERY:
[ ] All entry points enumerated (not sampled)
[ ] Trust boundaries mapped with privilege levels
[ ] Each entry point tested against vulnerability patterns
[ ] Attack trees built for each candidate finding
[ ] PROXIMITY tracked for each exploitation attempt

PoC & DYNAMIC VALIDATION (MANDATORY):
[ ] PoC constructed for each confirmed finding
[ ] Target running in production-representative config (NOT dev mode)
[ ] Each PoC executed against live system with output captured
[ ] Control test run for each finding (fix prevents the issue)
[ ] dynamic_status recorded: CONFIRMED / PARTIAL / FAILED
[ ] Any FAILED findings removed from report
[ ] Any DEV-MODE-DEPENDENT findings flagged and severity capped

NOVELTY & CLASSIFICATION:
[ ] Novelty verified (CVE check, advisory check, variant analysis)
[ ] Severity assessed using privilege-aware matrix
[ ] Each finding crosses a trust boundary (not a tautology)
[ ] Each finding works on default/common configuration (not test harness)
[ ] Report includes reproduction steps, dynamic evidence, impact, and fix
```

---

## Red Flags: STOP and Reconsider

| You're thinking... | Reality |
|---|---|
| "I verified it statically, that's enough" | No. If it doesn't work against a running system, it doesn't ship. |
| "Root can read secret data — CRITICAL!" | Root is inside the trust boundary. By-design. |
| "Same key = same output — key reuse vuln!" | That's the mathematical definition of the algorithm. |
| "This endpoint is unauthenticated!" | Check if the spec requires it to be unauthenticated. |
| "My PoC works perfectly!" | Did it work because of your test setup, or despite default config? |
| "I found 40 vulnerabilities!" | If 35 are by-design, you found 5 vulnerabilities and 35 credibility problems. |
| "This is definitely a 0-day!" | Did you check the CVE database? The project's changelog? |
| "The kill chain achieves full compromise!" | Does step 1 require a token that already grants full compromise? |
| "Case sensitivity is a bug!" | Is the entire system case-sensitive by design? |

---

`Five findings that change the system are worth more than forty that describe how it already works.`
