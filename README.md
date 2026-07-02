# Hardware-Vulnerabilities

# Abstract

Verilog is a Hardware Description Language (HDL) that allows circuits to be represented as a programming language. Like software-based programming languages, hardware-based HDLs are prone to bugs that jeopardize the security of the circuit, favoring malicious actors. Along with this, hardware vulnerabilities cannot be patched after production, as the circuits are permanently engrained in silicon. These vulnerabilities, known as Common Weakness Enumerations (CWEs), allow for easy grouping and identification, with most hardware related CWEs involving improper access control, exposed sensitive data, and unintended privilege escalation. To aid in detecting CWEs, we have developed a methodology to identify and minimize the occurrence of CWEs with the use of a Large Language Model (LLM).
<!-- Add more to this section later. -->
# 1. Introduction
Due to the constant improvement and evolution of software security, computers have become increasingly difficult for adversaries to exfiltrate personal information from. However, even if the software on a device is secure, its hardware can still be prone to vulnerabilities that nullify software-protections. Most circuits can be represented by a hardware description language (HDL), like a programming language. An example of an HDL is Verilog, which can describe circuits at the Register Transfer Level (RTL), which is a combination of the dataflow between circuit components and the intentional functionality of the system (Meng et al. 2025). However, if a circuit with a bug is produced, that bug becomes permanent as the physical circuit is created (Baleegh et al. 2024). As a result, MITRE has created a list called Common Weakness Enumerations (CWE), consisting of different groups of these vulnerabilities on a device's software or hardware based on its design. Hardware-based CWEs can lead to unauthorized data exposure, privilege escalation, and other issues if not properly checked. 

According to Meng et al (2025), the main bugs within Verilog RTL involve assignment statements, variable declaration statements, and if-statements, all of which are common within complex circuits. An issue that arises with the increasing number of bugs is that manual debugging has become more tedious. Therefore, hardware designers have started to employ language learning models (LLMs) such as MAGE and AIVRIL as a means of RTL code repair, particularly with locating errors and creating testbenches (Paria and Bhunia, 2026). However, LLMs are prone to hallucination, and lack the sufficient knowledge required to provide repair without needing a human to review it properly for any additional bugs (Alsaqer et al. 2024). Therefore, we propose a new framework to not only make the task of debugging RTL Verilog code less tedious but also provide a guide to automate LLMs to debug and repair RTL code more efficiently.

# 2. Motivation
We created our methodology to simplify the task of locating and fixing bugs for both individuals and LLMs; Finding them earlier throughout the hardware design process makes it easier to fix, and reduces potential costs in replacing faulty hardware in the future. In addition, LLMs have become increasingly relevant in the field of cybersecurity, and hardware designers have begun using LLMs to simplify tasks such as testbench creation. In some cases, LLMs have shown themselves to contribute to more accurate and effective RTL repairs (Alsaqer et al. 2024). However, the main struggle of LLMs in hardware design is that due to their lack of knowledge in the subject and inherent bias against hardware design, they often struggle with more complex circuits. (Paria and Bhunia, 2026). This issue is contributed due to under-constrained repair: A bug in RTL code allows the LLM to determine multiple different methods on how to fix it, regardless of if they are relevant to the design (Mastora and Sullivan, 2026). Underconstrained repair is primarily caused by three main factors: prompting, data scarcity, and long context processing, all of which can interfere with the learning of the LLM, preventing it from obtaining a true answer (Liu et al, 2026). Therefore, this framework is also meant to ensure that LLMs obtain proper fine-tuning to ensure that they will be able to assess hardware design more accurately, and eventually reduce the requirment of human assistance.
## 2.1 Related Works
<!--Insert Related Works Section Here-->
The Verilog LLM-Aided Vulnerability Detection framework (VerilogLAVD) by Long et al. (2026) explores the idea of LLMs detecting vulnerabilities by creating a property graph based on its structure and detecting its vulnerabilities based on its time-related edges. The researchers assess the performance of multiple LLMs using this method through their quality, reliability and practicality to determine that this method has greatly improved LLM’s ability to detect vulnerabilities within Verilog code. However, one of the largest weaknesses within their research was the context limit of the LLM when processing data.

According to a survey by Liu et al. (2026), the three main challenges of LLMs in hardware security are prompting due to the requirement of strong expertise in hardware security, the scarcity and cost of obtaining data, and long context processing, as if it surpasses its intended capacity, the LLM will lose information, forgetting its original “thought” process. Researchers such as Liu and Knechtel et al. (2026) suggest that the main solution for these issues is to fine-tune the LLM so that it best understands the semantics of Verilog and other important pieces of knowledge on hardware security. Going further on this point, Liu proposes the idea of multiple agents breaking down the task of debugging RTL code. For example, The MAGE LLM not only has a Verilog checking mechanism to detect early errors but also has four agents for the tasks of RTL generation, testbench generation, simulation, and debugging respectively. Meanwhile, AIVRIL utilizes two different agents, one for RTL generation, and one to review the code for errors.

Our methodology hopes to build on the idea of VerilogLAVD by analyzing hardware CWEs to allow both people and fine-tuned LLMs to better understand and reiteratively improve on their Verilog RTL code to minimize the number of possible exploits within circuits.
# 3. Methodology

Our methodology was designed through the analysis of CWE entries (MITRE, 2025), previous works, and iterative testing with the goal of providing an effective and efficient method to identify vulnerabilities that individuals with limited knowledge can utilize. We have limited our methodology and research to the listed CWEs on MITRE's 2025 Most Important Hardware Weaknesses list to target commonly seen vulnerabilities. 2 CWE entries on this list were omitted due to these vulnerabilities arising from microarchitectural design considerations.
### Complete list of CWEs:
- 226: Sensitive Information in Resource Not Removed Before Reuse
- 1189: Improper Isolation of Shared Resources on System-on-a-Chip (SoC)
- 1191: On-Chip Debug and Test Interface With Improper Access Control
- 1234: Hardware Internal or Debug Modes Allow Override of Locks
- 1247: Improper Protection Against Voltage and Clock Glitches
- 1256: Improper Restriction of Software Interfaces to Hardware Features
- 1260: Improper Handling of Overlap Between Protected Memory Ranges
- 1262: Improper Access Control for Register Interface
- 1300: Improper Protection of Physical Side Channels

Given an RTL Design, the role and features of the module are first identified. The module is then analyzed to determine important assets, behavior, data, and control flow. A CWE-driven review is then done utilzing the results of the analysis and module to identify potential vulnerabilties. A testbench is then created based off of potential / suspected vulnerabilities. The module is tested using the testbench, and reparied utilizing CWE-Design rules until the module passes simulation.

<img width="917" height="476" alt="CWE Detection Methodology Flowchart" src="https://github.com/user-attachments/assets/75bb6aa5-7993-4285-9308-ac51683d81b9" />

##### Figure 1: High-Level Graph of Methodology

## 3.1 Type Classification
The role of the module and any potential features are first identified. The AI model is given the (potentially) buggy module, along with a list of Module Types / Features and their corresponding potential CWEs (Figure 2). The AI model is instructured to identify any of the features on the list present in the given RTL design. It is possible to have multiple features in the design depending on the complexity of the module. 

By identifying these features, we are able to narrow down the amount of CWEs to look for when conducting the CWE-Driven review; It would be unnecessary to check for an improper JTAG authentication in a module that does not have a JTAG interface for example. Reviewing all CWEs also increases the risk of providing an overwhelming amount of information to the AI, potentially degrading its performance. The selected CWEs are recorded as potential vulnerabilities that will be reviewed in the CWE-Driven review.

<img width="1178" height="265" alt="CWE Vulnerability Table" src="https://github.com/user-attachments/assets/7492367d-0e89-4a0e-877b-163cd67bf3a0" />

##### Figure 2: List of Module Types / Features and Corresponding CWEs

## 3.2 Asset Identification
Next, any important assets are to be identified. The AI model is given the RTL design, the previously found module type, and features, and is instructed to identify any important assets, behavior, and functionality of the module. This includes important assets such as keys, privilege bits, etc., boundaries between privilege domains, clock behavior, reset schemes, potential adversary capabilities, security rules set in place such as restrictions on data, and finite state machines, including their transition rules, illegal states, etc. The AI model returns a list of its findings that will be utilized in the CWE-Driven review.

Generally, identifying the important assets of a module will help guide the AI model into the kinds of problems the module may have, along with verifying its understanding of the module itself. This also aids in the CWE-Driven review, as the AI has a better understanding of where to look for potential vulnerabilities in the RTL design, improving its efficiency and effectiveness.

## 3.3 Dependency Graph Analysis

A Program Dependency Graph (PDG) is then created and analyzed. Gvien the RTL design, the AI model is instructed to generate a PDG that models the data and control flow of the design. The nodes of the graph consists of any signals, registers, and gates. The edges of the graph consist of data-flow and control-dependency relationships. Based off of the generated graph, the AI model is then instructed to perform the following analyses:
- Reachability Analysis: Determine whether one node can be reached from another through a path in the graph.
- Dominance Analysis: Determine whether one node must always be encountered before another node
- Tain Propagation Analysis: Track how information originating from an untrusted source flows through the design.

The AI model returns the results from the performed analyses, consisting of the behaviors, controls, and potential vulnerabilities of the design. Through graph creation and analysis, the AI model is able to better define the behavior and design of the module, and potentially find vulnerabilities prior to the CWE-Driven Review. These results are all fed into the CWE-Driven review to aid in vulnerability identification in the module.

## 3.4 CWE-Driven Manual Review
Utilizing the module and the results from the analysis, a CWE-driven review is performed. The AI model is given the RTL design, the identified key assets, the results from the PDG analysis, and relevant CWE guides. The AI model is instructed to utilize the given data, and follow all given CWE guides to identify vulnerabilities in the module.

CWE guides are chosen based on suspected / potential CWEs determined from module / asset / behavior identification, and graph analysis results. The CWE guides were developed through analysis of their respective CWE entries, including their common causes, and identification methods, with the goal of including common scenarios where these vulnerabilities may occur. The AI model is only given relevant CWE guides based off of its previous findings as to not overwhelm the AI model with too many instructions that may potentially degrade performance. Each listed CWE contains a brief description of the vulnerability, questions to guide thinking, common causes of the vulnerability, and a checklist to aid in their identification. The AI models returns a list of its found vulnerabilities with its corresponding CWE entry, along with a description of the issue in the module. These results are then used to generate a testbench to verify these vulnerabilities.

The complete list of CWE guides can be found in the prompting directory of this repository.

## 3.5 Testbench Generation
Utilizing the previously found vulnerabilities, a testbench for the RTL design is created. The AI model is given the RTL design, the found vulnerabilities (if any), and a list of CWE secure design rules, and is instructed to generate a testbench that targets all found vulnerabilities and the validity of the given secure design rules for each CWE. Similar to the CWE guides, a list of CWE design rules were created for each CWE. These design rules were developed through analysis of their corresponding CWE entries, including their mitigation methods, and common mistakes that lead to these vulnerabilities. All testbench tests should be reviewed for potential errors, as a false pass / fail may negatively impact performance and code repair.

The complete list of CWE design rules can be found in the prompting directory of this repository.

## 3.6 Simulation
The generated testbench is then compiled and ran to test the given RTL design under the generated tests. If all tests pass, the given RTL module passes inspection, and all testing and analysis is completed. If one of more tests fail, the RTL design will then undergo a code repair (3.7).

## 3.7 Code Repair
Utilizing the results from the simulation, the RTL design will undergo code repair. The AI model is given the RTL design, all failed testbench tests, and the list of CWE design rules. The AI model is instructed to fix the module based off of the failed tests from the testbench simulation, while utilzing the CWE design rules as a guide for code repair. The AI model is also instructed to generate an updated testbench if changes to the RTL design were made that make it incompatible to the previously generated testbench (e.g. a new input). Once the fixed module (and potentially updated testbench) is generated, the simulation step is repeated (3.6) testing the repaired RTL design.

# 4. Results

# 5. Conclusion

# 6. References
<!--APA Format-->
MITRE. (2025, August 18). CWE - 2025 Most Important Hardware Weaknesses. https://cwe.mitre.org/topHW/archive/2025/2025_CWE_MIHW.html

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
