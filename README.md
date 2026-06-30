# Hardware-Vulnerabilities

# Abstract

Verilog is a Hardware Description Language (HDL) that allows circuits to be represented as a programming language. Like software-based programming languages, hardware-based HDLs are prone to bugs that jeopardize the security of the circuit, favoring malicious actors. However, a key difference is that hardware vulnerabilities cannot be patched after production, as the circuits are permanently engrained in silicon. These vulnerabilities, known as Common Weakness Enumerations (CWEs) allow for easy grouping and identification, with most hardware related CWEs involving improper access control, exposed sensitive data, and unintended privilege escalation. As a result, we have developed a methodology identify and minimize the occurrence of CWEs with the use of a Learning Language Model (LLM).
<!-- Add more to this section later. -->
# 1. Introduction
Due to the constant improvement and evolution of software security, computers have become increasingly difficult for hackers to exfiltrate personal information from. However, even if the software on a device is completely secure, its hardware can still expose important data. As a result, MITRE has created a list called Common Weakness Enumeration (CWE), contain different groups of these vulnerabilities on a device's software or hardware based on its design. These vulnerabilities are also caled Common Weakness Enumerations (CWEs). In particular, hardware-based CWEs, represented in the hardware description language (HDL) Verilog, can lead to unauthorized data exposure, priviledge escalation, and other issues if not properly checked. 
# 2. Motivation
<!-- It's important to find CWEs early before they become an issue later. -->
<!--LLMs have an increasing amount of relevance in the field of cybersecurity and can be used to simplify the task. -->
# 3. Methodology

Our methodology was designed through analysis of CWEs, previous works, and constant testing, with the goal of providing an effective and efficient method to identify vulnerabilities. The figure below models the workflow of the methodology.

<img width="1040" height="588" alt="Flow" src="https://github.com/user-attachments/assets/c60b714a-4af1-452e-b5ad-e9e287552014" />

Given an RTL Design, the role and features of the module are first identified. The module is the module is then analyzed to determine important assets, behavior, data, and control flow. A CWE-driven review is then done utilzing the results of the analysis and module to identify potential vulnerabilties. A testbench is then created based off of potential / suspected vulnerabilities. The module is tested using the testbench, and reparied utilizing CWE-Design rules until the module passes simulation. 


## Identify Module
The role of the module and any potential features are first identified. These directly correspond to potential vulnerabilities, and are noted for identification.

<img width="1178" height="265" alt="Screenshot 2026-06-30 103359" src="https://github.com/user-attachments/assets/7492367d-0e89-4a0e-877b-163cd67bf3a0" />

## Identify Assets and Behavior
The module, its roles, and features are then analyzed to determine:
- Important assets such as keys, privilege bits, lifecycle states, etc.
- Boundaries between privilege domains (privileged / unprivileged)
- Clock behavior and reset schemes
- Potential adversary capabilities
- Security rules set in place, e.g. restrictions on certain data
- Finite State Machine states, transition rules, illegal states

From these findings, a Program Dependency Graph is then created, modeling the behaviors and controls of the module. The nodes consists of any signals, registers, and gates. The edges consist of data-flow and control-depdendency relationships. The following is then performed on the graph:
- Reachability Analysis: Determine whether one node can be reached from another through a path in the graph.
- Dominance Analysis: Determine whether one node must always be encountered before another node
- Tain Propagation Analysis: Track how information originating from an untrusted source flows through the design.

## CWE-Driven Manual Review
Utilizing the module, and the results from the analysis, a CWE-driven review is performed. CWE reviews are chosen based on suspected / potential CWEs determined from module / asset / behavior identification, and graph analysis. Each listed CWE contains a brief description of the vulnerability, questions to guide thinkg, common causes, and a checklist to aid in identification.

### CWE-226 - Sensitive Information in Resource Not Removed Before Reuse
Situations where a resource holding sensitive data is reassigned or reused without being cleared, potentially leaking secrets

#### Core question to ask for sensitive registers:
1.	Is there a guaranteed zero-write before this resource is reused or made accessible to another context?

#### What to look for:
1.	Registers reused without explicit reset: Look for registers that hold sensitive values that get reassigned or repurposed without a clearing step in between
2.	FSM state transitions that skip a clear phase. Look for state machines that move from a “sensitive operation” state to an “idle/available” state without wiping intermediate registers
3.	Memory/RAM blocks reused across security contexts: Look for shared RAM or register files where one “owner” finished and another begins with no explicit zeroing between allocations.
4.	Reset logic that doesn’t cover sensitive registers: Check that async/sync reset paths explicitly clear sensitive registers, a partial reset is a common issue.
5.	Power on/reinitialization sequence: Look for initialization blocks (initial) or power-cycle sequences that assume registers start at zero without explicitly assigning them.

#### Checklist:
-	All keys / secret buffers are zeroed before deallocation or context switch
-	Scrubs occur on ALL exit paths (error, timeout, normal release)
-	Hardware scrubber completion is signaled before resource-free assertion

### CWE-1189 - Improper Isolation of Shared Resources on System-on-a-Chip (SoC)
Shared resources accessible by multiple IP blocks or trust domains without proper isolation, allowing lower-trust agents to interfere with or observe high-trust agents’ data

#### Core questions to ask:
1.	Are all shared resources (memory, accelerators, buses) partitioned by trust domain with explicit access checks?
2.	Are interrupt lines separated or tagged so non-secure peripherals cannot infer secure peripheral activity?
3.	Do all bus transactions carry a master ID and security attribute that the logic validates?
4.	Can a lower-privilege domain trigger a reset or clock gate that affects a higher-privilege domain?

#### What to look for:
1.	Shared memory with no access partitioning: Look for memory mux logic that selects between multiple masters without any checks.
2.	Shared interrupt lines with no source isolation: Look for interrupt signals that OR together sources from different trust domains, a non-secure peripheral sharing a line with a secure one leaks activity timing to the non-secure world.
3.	Shared bus with no transaction tagging: Look for bus transactions that carry no master ID, security attribute, or privilege level signal. Without tagging, no access control decisions can be made
4.	Shared clock/reset domains across trust boundaries: Look for a single reset or clock-gate signal shared between secure and non-secure domains. A non-secure agent triggering a reset can disrupt or clear a secure domain’s state.

#### Checklist:
-	Every shared SRAM / cache bank has a domain tag or range firewall
-	Domain tags are hardware-assigned and not software-writable
-	Shared resources are flushed / scrubbed on domain context switch
-	All shared resources (memory, accelerators, buses) partitioned by trust domain have explicit access checks

### CWE-1191 – On-Chip Debug/Test Interface with Improper Access Control
Covers debug and test interfaces (e.g. JTAG) that are accessible without proper authentication or authorization checks

#### Core questions to ask:
1.	Is debug access gated by more than one factor (e.g. lifecycle and authentication)?
2.	Are sensitive registers excluded from scan chains (testing modes)
3.	Does debug access have address/register range restrictions?
4.	Is the debug interface properly disabled in production?
5.	Are there any hardcoded credentials that unlock debug?
6.	Are outputs being masked when appropriate? 

#### What to look for:
1.	JTAG/Debug ports with no authentication gate: Look for debug interfaces that become active based solely on a single unprotected pin or signal, with no credential checks
2.	Debug/test modes controlled by fuse or strap with no further checks: Watch for lifecycle/strap signals that unlock debug with no secondary verification.
3.	Scan chain exposure of sensitive registers: Check whether sensitive registers are directly included in scan chains without being excluded or obfuscated
4.	Debug registers that allow arbitrary memory or CSR access: Look for debug backdoors that can read/write any address without range restrictions or privilege checks
5.	Missing or by-passable authentication FSM: Look for authentication state machines that have weak transitions, reachable “authenticated” states without completing the full challenge-response sequence.
6.	Debug interfaces active in production lifecycle states: Look for lifecycle/mode checks that do not properly disable debug in production/secure boot modes.
7.	Test/Design for Testability logic not properly isolated: Watch for DFT structures that can be activated at runtime and expose internal state (such as a test mode)
8.	Hardcoded debug credentials: Scan for hardcoded passwords or keys used to unlock debug access

#### Checklist:
-	JTAG disabled via OTP fuse in production builds
-	Authenticated unlock required even when debug fuse is not blown
-	Debug mode cannot override lock bits, fuses, or MPU rules
-	Scan chains cannot capture or shift security-critical register contents
-	No debug signal reaches a locked register write path

### CWE-1234 - Hardware Internal or Debug Modes Allow Override of Locks
Debug or test modes that, when activated, bypass or override security lock bits, undermining protections that were correctly implemented for normal operation.

#### Core questions to ask:
1.	Does any debug, test, or scan mode signal appear as an alternative condition on a lock-protected write path?
2.	Can scan_rst, test_rst, or any externally controllable reset clear a lock bit register?
3.	Are there JTAG instructions that write to registers without checking the corresponding lock bit?
4.	Can a lifecycle downgrade transition zero out lock bits that were set during a prior lifecycle state?
5.	Are there any shadow or alternate write paths to sensitive registers that bypass lock enforcement?

#### What to look for:
1.	Debug mode unconditionally overrides a lock bit: Look for write-enable logic where debug_mode is OR’d in as an alternative condition, effectively making the lock bit irrelevant whenever debug is active
2.	Test/scan mode clears or resets lock registers: Look for scan or test reset signals that drive lock bit registers to zero. An attacker who can assert scan_rst can clear any lock and regain write access to protected registers
3.	JTAG instruction that directly writes locked registers: Look for JTAG data register instructions that write directly to security-critical registers without consulting the corresponding lock bit, the JTAG command becomes a lock bypass.
4.	Lifecycle downgrade re-enabling locks that were set: Look for lifecycle transitions back to a development state that zero out lock registers, allowing attackers to deliberately downgrade lifecycles to clear locks set in production
5.	Shadow registers in debug mode that bypass lock enforcement: Look for mux-style assignments where debug_mode selects a direct write path to a sensitive registers, completely bypassing the lock=checked normal write path

#### Checklist: 
-	Authenticated unlock required even when debus fuse is not blown
-	Debug mode cannot override lock bits, fuses, or MPU rules
-	Scan chains cannot capture or shift security-critical register contents
-	No debug signal reaches a locked register write path

### CWE-1247 - Improper Protection Against Voltage and Clock Glitches
No detection or response logic for fault injection via voltage droops or clock anomalies, allowing an attacker to skip instructions, corrupt comparisons, or bypass security checks

#### Core questions to ask:
1.	Are there any security-critical comparisons protected by redundant checks across multiple cycles or logic cones?
2.	Is there a clock frequency monitor or reference oscillator comparison that detects out-of-range clock speeds?
3.	Are external-reset signals filtered for minimum pulse width before being acted on?
4.	Do retry counters use saturating arithmetic and is the lockout condition checked in a glitch-resistant way?

#### What to look for:
1.	Single-cycle security decisions with no redundancy: Look for authentication or access grant logic that resolves in a single clock cycle with no redundant check. A precisely timed clock glitch on that cycle can cause the comparison to be skipped.
2.	No clock integrity / frequency monitoring logic: Look for designs that have no reference oscillator comparison, no frequency watchdog, and no out-of-range clock detection. The design blindly trusts whatever clock is presented to it.
3.	Reset logic with no glitch filter: Look for asynchronous resets driven directly from an external pin with no debounce or minimum-pulse-width filter. A brief glitch on the reset pin can cause unintended partial reset.
4.	Security-critical counters or FSMs with no error state: Look for retry counters or lockout FSMs where the increment and threshold check happen in a way that a glitch on a single cycle can prevent the counter from reaching its lockout value.
5.	No voltage/clock glitch detection registers or interrupts: Look for a complete absence of any glitch_detected, brownout_detected, or freq-error signal in the design. Without detection, there is no response path even if the silicon has glitch sensors

#### Checklist:
-	Voltage / frequency monitors present with lockdown on violation
-	FSM state encoding analyzed for glitch-reachable dangerous states
-	Setup / hold violation detectors on security-critical flip-flops

### CWE-1256 - Improper Restriction of Software Interfaces to Hardware Features
Software-accessible registers or CSRs expose hardware features that should be privileged-only, but are reachable by unprivileged software.

#### Core questions to ask:
1.	Are all registers that control clocks, resets, and power domains gated behind a privilege level check?
2.	Can unprivileged software write DMA source, destination, or size registers that could redirect transfers into secure memory?
3.	Do any registers mix unprivileged and privileged fields at the same address without per-field access control?
What to look for:
1.	Power / clock control registers with no privilege gate: Look for registers that control clock gating, power domain switching, or IP resets that can be written by any bus master without a privilege level check. Unprivileged software can deny service to other components
2.	DMA configuration accessible without privilege check: Look for DMA source, destination, and size registers writable without privilege gating. Unprivileged software can reprogram DMA to read from or write to secure memory regions
3.	Hardware feature enable bits in mixed-privilege registers: Look for registers that pack both benign unprivileged fields and dangerous privileged fields into the same address. A full width write by unprivileged software modifies both

#### Checklist:
-	All hardware control registers (clocking, power, remapping) are privilege-gated
-	Hardware control registers are locked after boot configuration
-	No unprivileged software can reach hardware-only controls
-	Separate address ranges for hardware-control vs software-status registers

### CWE-1260 - Improper Handling of Overlap Between Protected Memory Ranges
Memory protection logic that has overlapping region definitions and resolves conflicts in an insecure way. Allows bypasses of intended protections

#### Core questions to ask:
1.	When two regions definitions overlap, does the hardware apply the most restrictive or least restrictive policy?
2.	Is there a defined and verified priority order for region checks, and does more secure always beat less secure?
3.	Are boundary conditions (< vs <=) consistent and verified at every region edge to eliminate gaps or double-coverage?
4.	For software-programmable regions, is there hardware logic that detects and rejects overlapping region definitions?
5.	Does any conflict resolution logic default to ALLOW rather than DENY?

#### What to look for:
1.	Overlapping ranges resolved by “most permissive wins”: Look for access_ok logic that OR’s together multiple region hit signals. If a less restrictive region overlaps a more restrictive one, the OR means the open region’s permissions with for addresses in the overlap zone.
2.	Priority encoding that favors lower-security regions: Look for loop-based region checks where later iterations overwrite earlier results. If lower-security regions are checked last, they can override higher-security decisions for overlapping addresses.
3.	Off-by-one errors in range bounder checks: Look for boundary conditions using < vs <= inconsistently across adjacent regions. A signal address at the exact boundary may fall into the wrong region or into an unprotected gap between regions.
4.	Region size computed dynamically without overlap detection: Look for software-programmable regions where the top address is computed as base + size at runtime with no hardware logic to detect or reject overlaps with existing protected regions.
5.	Attribute conflict resolution defaulting to permissive: Look for explicit overlap detection logic that resolves the conflict by granting access. The safe default for any ambiguous or confliction region match should always be deny.

#### Checklist:
-	No two regions produce conflicting permissions for any address
-	Hardware detects overlapping region configurations
-	Tie-break / priority rule is documented and formally verified
-	Default response for conflict is deny

### CWE-1262 - Improper Access Control for Register Interface
Covers situations where hardware registers containing sensitive configuration, security settings, or privileged data can be read or written by untrusted software or hardware without proper access control checks.

#### Core questions to ask:
1.	Is every sensitive register protected, or just a subset?
2.	Are lock bits set-only, and checked on every write path?
3.	Are privilege/trust signals hardware-derived, and not software-writable?
4.	Is the access policy default-deny rather than default-allow?
5.	Are both read and write paths protected?

#### What to look for:
1.	No privilege/trust level check on register writes: Look for register write logic that accepts writes from any bus master without checking the requester’s privilege level
2.	Missing read access control on sensitive registers: Look for register read paths that return sensitive data regardless of who is requesting it
3.	Trust/privilege signals that are software-controllable: Look for privilege or trust signals that can be set by software rather than begin hardware-derived from a trusted source
4.	Lock bits that are never enforced/Unused inputs: Look for registers that have a defined lock bit in the spec., but the lock is never actually checked/used, or variables (such as a priv. level) that are never used/checked.
5.	Lock bits that can be cleared after being set: Even when the lock bit is checked, ensure that they can only transition one way, and cannot be unlocked once set.
6.	No access control on range of registers, only spot checks: Look for decoders that protect a few specific addresses but leave neighboring addresses in a sensitive block unprotected
7.	Default-open access policy: Look for access control logic structed as “deny specific addresses” rather than “allow specific addresses”, a missing entry means open access.

#### Checklist:
-	All security CSRs have hardware privilege-check logic on write paths.
-	Key / secret registers are write-only (mask reads / return 0s )
-	Write-once lock bits gate all security configuration registers

### CWE-1300 - Improper Protection of Physical Side Channels
RTL implementation leaks information through power consumption, EM emissions, or timing variation that correlates with secret data.

#### Core questions to ask:
1.	Do any combinational paths have switching activity that is statistically correlated with secret key bits?
2.	Are there any branches, mux selections, or operand choices controlled directly by secret data?
3.	Are all secret comparisons constant-time with no early exit paths?

#### What to look for:
1.	Unbalanced switching activity on secret-dependent data paths: Look for operations where the output switching activity directly depends on the Hamming weight or Hamming distance of a secret value. Power consumption becomes a statistical oracle for the key.
2.	Secret-dependent branching or operand selection: Look for if/case statements that select different operations, datapaths, or operands based on a secret bit. Different branches have different power profiles and propagation delays, leaking the secret through timing or power.
3.	Non-constant-time comparison for authentication: Look for comparison loops with early-exit break conditions. The number of cycles taken before failure reveals how many bytes of the secret matched the input, enabling byte-at-a-time attacks.

#### Checklist:
-	All key-dependent logic uses mux (not if/case) for selection
-	No early-exit in crypto loops or comparators
-	Timing of key-dependent operations is data-independent


## Test Benches for CWEs
Based on previous analysis and review, a testbench is then created to target all potential / suspected vulnerabilities. For each CWE, a list of tests are given to test the module, however more tests should be included depending on the behavior and complexity of the module.

### Testbench Rules

#### CWE-226 - Sensitive Information in Resource Not Removed Before Reuse
1.	After a resource (memory, register, buffer) is released and reallocated, verify the new owner cannot read prior contents by writing a known pattern. 
2.	Confirm data is zeroed or overwritten before new access.
3.	Testbench should check that any important data is removed from the circuit before any transitions.

#### CWE-1189 - Improper Isolation of Shared Resources on System-on-a-Chip (SoC)
1.	On shared SoC buses/memory, verify one IP block cannot read/write another’s protected regions. 
2.	Test that untrusted software is denied access to secure memory and registers.
3.	Testbench should ensure that trusted and untrusted users have separate resources (wires, registers, etc.)

#### CWE-1191 – On-Chip Debug and Test Interface With Improper Access Control
1.	Confirm JTAG/debug interfaces are disabled or require authentication in production mode. 
2.	Attempt debug register reads/writes without credentials to verify denial. 
3.	Test that debug mode cannot be re-enabled from unprivileged software.
4.	Testbenches should properly check permissions of the user and reject/hide important resources from them if they do not have sufficient permissions.

#### CWE-1234 - Hardware Internal or Debug Modes Allow Override of Locks
1.	Set a lock bit, then attempt to override it by entering debug or test mode. 
2.	Verify lock persists across mode transitions. 
3.	Confirm debug modes cannot write to registers that were locked in normal operation.
4.	Testbenches should ensure that only authorized users can use debug mode or ensure that debug mode signals do not interfere with reset logic.

#### CWE-1247 - Improper Protection Against Voltage and Clock Glitches
1.	Apply out-of-spec voltage or clock frequency stimuli. 
2.	Verify the design has glitch detection logic that triggers a lockout or reset.
3.	Testbenches should ensure that no abnormal changes occur in the event of a clock/voltage glitch (clock stops moving or skips a few seconds, etc.)

#### CWE-1256 - Improper Restriction of Software Interfaces to Hardware Features
1.	Verify that software-accessible interfaces cannot directly manipulate hardware features that should be hardware-only.
2.	Testbenches should check that software interfaces will have no effect on hardware-exclusive functions.

#### CWE-1260 - Improper Handling of Overlap Between Protected Memory Ranges
1.	Define two overlapping protected memory ranges and test what happens at the overlap boundary. 
2.	Verify the stricter policy wins. 
3.	Check that address +-1 around boundaries enforces the correct permission and no region is accidentally unprotected.
4.	Testbenches should check that the memory addresses between the two protected memory ranges don’t overlap with each other.

#### CWE-1262 - Improper Access Control for Register Interface
1.	Test that privilege level cannot be self-elevated via a register write: De-escalate only
2.	From unprivileged mode, attempt to read and write to every register. Confirm privileged registers are not writable.

#### CWE-1300 - Improper Protection of Physical Side Channels
1.	Measure whether operations on secret data produce distinguishable timing or power signatures. 
2.	Test that encryption/decryption of different keys takes a constant number of cycles.
3.	Testbenches should ensure that the circuit does perform any actions that allow users to guess what it is doing (calculations, character by character comparisons, etc.)

## Evaluate Needs
The module is then tested under the testbench, and if all tests pass, then testing is complete. Otherwise, for each failed test, utilize the corresponding CWE-based design entry, and repair / modify module until all tests pass.


### CWE-Based Design Rules

#### CWE-226 - Sensitive Information in Resource Not Removed Before Reuse
1.	Zero-fill or overwrite all memory, registers, and storage before releasing / reassigning resources, and on reset.
2.	During critical state transitions, information not needed in the next state should be removed or overwritten with fixed patterns (such as 0’s), before the transition to the next state
3.	Validate scrubbing is complete before reusing resources
4.	Overwrite cryptographic keys immediately after use.

#### CWE-1189 - Improper Isolation of Shared Resources on System-on-a-Chip (SoC)
1.	Enforce hardware access control at every shared resource
2.	When sharing resources, avoid mixing agents of varying trust levels. Untrusted agents should not share resources with trusted agents.
3.	Shared resources are flushed / scrubbed on domain context switch

#### CWE-1191 – On-Chip Debug and Test Interface With Improper Access Control
1.	Disable or permanently fuse-off debug interfaces (e.g. JTAG) in production silicon if possible, or implement authentication and authorization for the debug interfaces
2.	Debug mode cannot override lock bits, fuses, or MPU rules
3.	Limit debug visibility to non-sensitive registers. Important registers must never be exposed via debug paths. Security-sensitive data stored in registers should be cleared when entering debug mode

#### CWE-1234 - Hardware Internal or Debug Modes Allow Override of Locks
1.	Security lock bit protections should be reviewed for any bypass/override modes supported
2.	Design lock registers as a one-time programmable fuse
3.	Never allow a debug authentication to bypass lock evaluations
4.	Ensure that no combination of debug inputs can override lock state

#### CWE-1247 - Improper Protection Against Voltage and Clock Glitches
1.	Utilize an input from a glitch detector that overrides all operations to force a safe state (Error).
2.	Use multi-bit encodings instead of a single bit, as a glitch is highly unlikely to perfectly flip bits into exact configurations.
3.	Use defensive default states: If a glitch forces state machine registers into an undefined state, the system should default to an error state rather than failing open

#### CWE-1256 - Improper Restriction of Software Interfaces to Hardware Features
1.	Map security-sensitive hardware features to privilege-gated registers. Unprivileged software must receive a fault on access
2.	If needed, apply whitelisting only; Allow access to certain software instead of denying access to others
3.	Block unauthorized software from enabling security-sensitive features
4.	Ensure proper access control mechanisms protect software-controllable features altering physical operating conditions such as clock frequency and voltage

#### CWE-1260 Improper Handling of Overlap Between Protected Memory Ranges
1.	Ensure that memory regions are isolated as intended and that access control (read/write) policies are used by hardware to protect privileged software
2.	Detect overlapping addresses at the beginning and end of address space
3.	Default response for conflict is deny

#### CWE-1262 - Improper Access Control for Register Interface
1.	Assign explicit read/write permissions per privilege level for every register
2.	Default all security-sensitive registers to deny access
3.	Separate readable and writable permissions

#### CWE-1300 - Improper Protection of Physical Side Channels
1.	Implement constant-time algorithms for all cryptographic operations
2.	All key-dependent logic uses mux (not if/case) for selection
3.	Apply blinding or masking techniques to implementations of cryptographic algorithms




# 4. Results

# 5. Conclusion

# 6. References
<!--APA Format-->
Ahmad, B., Thakur, S., Tan, B., Karri, R., & Pearce, H. (2024). On Hardware Security Bug Code Fixes By Prompting Large Language Models. IEEE Transactions on Information Forensics and Security, 19, 1–1. https://doi.org/10.1109/tifs.2024.3374558

Alsaqer, S., Alajmi, S., Ahmad, I., & Alfailakawi, M. (2024). The potential of LLMs in hardware design. Journal of Engineering Research, 13(3). https://doi.org/10.1016/j.jer.2024.08.001

Cheung, B. (2025, December). Abstraction of Thought Makes AI Better Reasoners. Benny’s Mind Hack. https://bennycheung.github.io/abstraction-of-thought-makes-ai-better-reasoners

Knechtel, J., Sinanoglu, O., & Karri, R. (2026). LLMs for Secure Hardware Design and Related Problems: Opportunities and Challenges. In arXiv. https://arxiv.org/abs/2605.10807

Liu, H., Lu, Y., Wang, M., Yao, X., & Yu, B. (2026). LLM-Assisted Circuit Verification: A Comprehensive Survey. 2026 31st Asia and South Pacific Design Automation Conference (ASP-DAC), 439–446. https://doi.org/10.1109/asp-dac66049.2026.11420692

Long, X., Xia, Y., Kuang, L., Wan, Y., & Liu, Z. (2026). VerilogLAVD: LLM-Aided Pattern Generation for Verilog CWE Detection. ACL ARR 2026 January, 1, 28292–28308. https://aclanthology.org/2026.acl-long.1304.pdf

Mastora, M., & Sullivan, D. (2026). When Repairs Are Not Unique: Rethinking RTL Repair Benchmarks. Proceedings of the Great Lakes Symposium on VLSI 2026, 709–710. https://doi.org/10.1145/3787109.3815318

Mell, P., & Bojanova, I. (2024). Hardware Security Failure Scenarios: Potential Hardware Weaknesses. In NIST Computer Security Research Center. National Institute of Standards and Technology. https://doi.org/10.6028/nist.ir.8517

Meng, X., Ji, X., Zhang, G., He, J., Yang, D., Chen, F., Wang, J., Yu, C., Zhao, X., & Wu, J. (2025). Rtl design flaws revisited: a data-driven study of systematic bug patterns in Verilog code. The Journal of Supercomputing, 81(14). https://doi.org/10.1007/s11227-025-07811-9

Mukherjee, R., & Chakraborty, R. S. (2026). Detecting Hardware Trojans in High-Level Synthesis-Generated RTL using Large Language Models. ACM Transactions on Design Automation of Electronic Systems. https://doi.org/10.1145/3795509

Paria, S., & Bhunia, S. (2026). Harnessing the Power of LLMs for Enhancing Hardware Security. SN Computer Science, 7(2). https://doi.org/10.1007/s42979-026-04799-8

Qi, H., Du, Y., Zhang, L., Liew, S. C., Chen, K., & Du, Y. (2026). VeriRAG: A Retrieval-Augmented Framework for Automated RTL Testability Repair. 2026 27th International Symposium on Quality Electronic Design (ISQED), 1–8. https://doi.org/10.1109/isqed69900.2026.11534732
