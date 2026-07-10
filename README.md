# LLM-Assisted Detection and Repair of Hardware Security Vulnerabilities in Verilog Designs

# Abstract

Verilog is a Hardware Description Language (HDL) used to describe and implement digital circuits. Like traditional software programming languages, Verilog designs are susceptible to bugs that can introduce security vulnerabilities, creating opportunities for malicious exploitation. Unlike software vulnerabilities, however, hardware flaws are often difficult or impossible to patch after fabrication because they become permanently embedded in silicon. These weaknesses are commonly categorized using the Common Weakness Enumeration (CWE) framework, with many hardware-related CWEs involving improper access control, exposure of sensitive information, and unintended privilege escalation. To improve the detection of these vulnerabilities, we have developed a methodology that leverages a Large Language Model (LLM) to identify potential hardware CWEs in Verilog designs. This methodology was then tested iteratively on a dataset of single-module Verilog designs. This work demonstrates the potential of Large Language Models to augment traditional hardware security analysis by providing automated assistance in identifying security weaknesses within Verilog designs.

<!-- Add more to this section later. -->
# 1. Introduction
Due to the constant improvement and evolution of software security, computers have become increasingly difficult for adversaries to exfiltrate personal information from. However, even if the software on a device is secure, its hardware can still be prone to vulnerabilities that nullify software-protections. Most circuits can be represented by a hardware description language (HDL), like a programming language. An example of an HDL is Verilog, which can describe circuits at the Register Transfer Level (RTL), which is a combination of the dataflow between circuit components and the intentional functionality of the system (Meng et al. 2025). However, if a circuit with a bug is produced, that bug becomes permanent as the physical circuit is created (Ahmad et al. 2024). As a result, MITRE has created a list called Common Weakness Enumerations (CWE), consisting of different groups of these vulnerabilities on a device's software or hardware based on its design. Hardware-based CWEs can lead to unauthorized data exposure, privilege escalation, and other issues if not properly checked. 

According to Meng et al (2025), the main bugs within Verilog RTL involve assignment statements, variable declaration statements, and if-statements, all of which are common within complex circuits. An issue that arises with the increasing number of bugs is that manual debugging has become more tedious. Therefore, hardware designers have started to employ language learning models (LLMs) such as MAGE and AIVRIL as a means of RTL code repair, particularly with locating errors and creating testbenches (Paria and Bhunia, 2026). However, LLMs are prone to hallucination, and lack the sufficient knowledge required to provide repair without needing a human to review it properly for any additional bugs (Alsaqer et al. 2024). Therefore, we propose a new framework to not only make the task of debugging RTL Verilog code less tedious but also provide a guide to automate LLMs to debug and repair RTL code more efficiently.

# 2. Motivation
We created our methodology to simplify the task of locating and fixing bugs for both individuals and LLMs; Finding them earlier throughout the hardware design process makes it easier to fix, and reduces potential costs in replacing faulty hardware in the future. In addition, LLMs have become increasingly relevant in the field of cybersecurity, and hardware designers have begun using LLMs to simplify tasks such as testbench creation. In some cases, LLMs have shown themselves to contribute to more accurate and effective RTL repairs (Alsaqer et al. 2024). However, the main struggle of LLMs in hardware design is that due to their lack of knowledge in the subject and inherent bias against hardware design, they often struggle with more complex circuits. (Paria and Bhunia, 2026). This issue is contributed due to under-constrained repair: A bug in RTL code allows the LLM to determine multiple different methods on how to fix it, regardless of if they are relevant to the design (Mastora and Sullivan, 2026). Underconstrained repair is primarily caused by three main factors: prompting, data scarcity, and long context processing, all of which can interfere with the learning of the LLM, preventing it from obtaining a true answer (Liu et al, 2026). Therefore, this framework is also meant to ensure that LLMs obtain proper fine-tuning to ensure that they will be able to assess hardware design more accurately, and eventually reduce the requirment of human assistance.
## 2.1 Related Works
The Verilog LLM-Aided Vulnerability Detection framework (VerilogLAVD) by Long et al. (2026) explores the idea of LLMs detecting vulnerabilities by creating a property graph based on its structure and detecting its vulnerabilities based on its time-related edges. The researchers assess the performance of multiple LLMs using this method through their quality, reliability and practicality to determine that this method has greatly improved LLM’s ability to detect vulnerabilities within Verilog code. However, one of the largest weaknesses within their research was the context limit of the LLM when processing data.

According to a survey by Liu et al. (2026), the three main challenges of LLMs in hardware security are prompting due to the requirement of strong expertise in hardware security, the scarcity and cost of obtaining data, and long context processing, as if it surpasses its intended capacity, the LLM will lose information, forgetting its original “thought” process. Researchers such as Liu and Knechtel et al. (2026) suggest that the main solution for these issues is to fine-tune the LLM so that it best understands the semantics of Verilog and other important pieces of knowledge on hardware security. Going further on this point, Liu proposes the idea of multiple agents breaking down the task of debugging RTL code. For example, The MAGE LLM not only has a Verilog checking mechanism to detect early errors but also has four agents for the tasks of RTL generation, testbench generation, simulation, and debugging respectively. Meanwhile, AIVRIL utilizes two different agents, one for RTL generation, and one to review the code for errors.

Our methodology hopes to build on the idea of VerilogLAVD by analyzing hardware CWEs to allow both people and fine-tuned LLMs to better understand and reiteratively improve on their Verilog RTL code to minimize the number of possible exploits within circuits.
# 3. Methodology

Our methodology was designed through the analysis of CWE entries (MITRE, 2025), previous works, and iterative testing with the goal of providing an effective and efficient method to identify vulnerabilities that individuals with limited knowledge can utilize. We have limited our methodology and research to the listed CWEs on MITRE's 2025 Most Important Hardware Weaknesses list to target commonly seen vulnerabilities. Two CWE entries on this list (CWE-1421 and CWE-1423) were omitted due to these vulnerabilities arising from microarchitectural design considerations.
### Complete list of CWEs:
- CWE-226: Sensitive Information in Resource Not Removed Before Reuse
- CWE-1189: Improper Isolation of Shared Resources on System-on-a-Chip (SoC)
- CWE-1191: On-Chip Debug and Test Interface With Improper Access Control
- CWE-1234: Hardware Internal or Debug Modes Allow Override of Locks
- CWE-1247: Improper Protection Against Voltage and Clock Glitches
- CWE-1256: Improper Restriction of Software Interfaces to Hardware Features
- CWE-1260: Improper Handling of Overlap Between Protected Memory Ranges
- CWE-1262: Improper Access Control for Register Interface
- CWE-1300: Improper Protection of Physical Side Channels

Given an RTL Design, the role and features of the module are first identified. The module is then analyzed to determine important assets, behavior, data, and control flow. A CWE-driven review is then done utilzing the results of the analysis and module to identify potential vulnerabilties. A testbench is then created based off of potential and suspected vulnerabilities. The module is tested using the testbench, and reparied utilizing CWE-Design rules until the module passes simulation. We utilized Microsoft Copilot as the LLM to judge performance; Other models may yield different result.

<img width="831" height="450" alt="image" src="https://github.com/user-attachments/assets/ac63b12d-8b93-4d67-8c82-eba6235419ea" />

##### Figure 1: High-Level Graph of Methodology

Our methodology was tested on 32 Verilog single-module designs. Of these modules, 27 contained a corresponding CWE in its design. The remaining 5 modules were used to test the validity of our methodology and the AI model's ability to determine if a module contained vulnerabilities on modules that had no CWE. The Verilog modules were designed through study of the common causes of corresponding CWEs. Some modules were also obtained from the dataset of a previous study (Qi et al., 2026). The distribution of the modules are as follows:

- CWE-226: 6
- CWE-1189: 1
- CWE-1191: 1
- CWE-1234: 7
- CWE-1247: 1
- CWE-1256: 1
- CWE-1260: 1
- CWE-1262: 3
- CWE-1300: 6
- Non-Vulnerabilities: 5

## 3.1 Type Classification
The role of the module and any potential features are first identified. The AI model is given the (potentially) buggy module, along with a list of Module Types, Features and their corresponding potential CWEs (Figure 2). The AI model is instructured to identify any of the features on the list present in the given RTL design. It is possible to have multiple features in the design depending on the complexity of the module. 

By identifying these features, we are able to narrow down the amount of CWEs to look for when conducting the CWE-Driven review; It would be unnecessary to check for an improper JTAG authentication in a module that does not have a JTAG interface for example. Reviewing all CWEs also increases the risk of providing an overwhelming amount of information to the AI, potentially degrading its performance. The selected CWEs are recorded as potential vulnerabilities that will be reviewed in the CWE-Driven review.

<img width="1178" height="265" alt="CWE Vulnerability Table" src="https://github.com/user-attachments/assets/7492367d-0e89-4a0e-877b-163cd67bf3a0" />

##### Figure 2: List of Module Types, Features and Corresponding CWEs

## 3.2 Asset Identification
Next, any important assets are to be identified. The AI model is given the RTL design, the previously found module type, and features, and is instructed to identify any important assets, behavior, and functionality of the module. This includes the following: 
- Any important assets, such as keys, privilege bits, lifecycle states, etc.
- Boundaries between privilege domains (secure/non-secure, privileged/unprivileged, on-chip/off-chip). Each crossing is a potential vulnerability!
- Clock behavior and reset schemes
- Any adversary capabilities, such as potentially toggling JTAG pins, or manipulating the clock.
- Security rules set in place, such as restrictions on certain data.
- FSM states, transition-rules, illegal states

Generally, identifying the important assets of a module will help guide the AI model into the kinds of problems the module may have, along with verifying its understanding of the module itself. This also aids in the CWE-Driven review, as the AI has a better understanding of where to look for potential vulnerabilities in the RTL design, improving its efficiency and effectiveness.

## 3.3 Dependency Graph Analysis

A Program Dependency Graph (PDG) is then created and analyzed. Given the RTL design, the AI model is instructed to generate a PDG that models the data and control flow of the design. The nodes of the graph consists of any signals, registers, and gates. The edges of the graph consist of data-flow and control-dependency relationships. Based off of the generated graph, the AI model is then instructed to perform the following analyses:
- Reachability Analysis: Determine whether one node can be reached from another through a path in the graph.
- Dominance Analysis: Determine whether one node must always be encountered before another node
- Tain Propagation Analysis: Track how information originating from an untrusted source flows through the design.

The AI model returns the results from the performed analyses, consisting of the behaviors, controls, and potential vulnerabilities of the design. Through graph creation and analysis, the AI model is able to better define the behavior and design of the module, and potentially find vulnerabilities prior to the CWE-Driven Review. These results are all fed into the CWE-Driven review to aid in vulnerability identification in the module.

## 3.4 CWE-Driven Manual Review
Utilizing the module and the results from the analysis, a CWE-driven review is performed. The AI model is given the RTL design, the identified key assets, the results from the PDG analysis, and relevant CWE guides. The AI model is instructed to utilize the given inputs and follow all given CWE guides to identify vulnerabilities in the module.

CWE guides are chosen based on suspected or potential CWEs determined from module / asset / behavior identification, and graph analysis results. The CWE guides were developed through analysis of their respective CWE entries, including their common causes and detection methods, with the goal of including common scenarios where these vulnerabilities may occur. The AI model is only given relevant CWE guides based off of its previous findings as to not overwhelm the model with too many instructions, potentially degrade performance. Each listed CWE contains a brief description of the vulnerability, questions to guide thinking, common causes of the vulnerability, and a checklist to aid in their identification. The AI models returns a list of its found vulnerabilities with its corresponding CWE entry, along with a description of the issue in the module. These results are then used to generate a testbench to verify these vulnerabilities.

The complete list of CWE guides can be found in the prompting directory of this repository.

## 3.5 Testbench Generation
Utilizing the previously found vulnerabilities, a testbench for the RTL design is created. The AI model is given the RTL design, the found vulnerabilities (if any), and a list of CWE secure design rules, and is instructed to generate a testbench that targets all found vulnerabilities and the validity of the given secure design rules for each CWE. Similar to the CWE guides, a list of CWE design rules were created for each CWE. These design rules were developed through analysis of their corresponding CWE entries, including their mitigation methods, and common mistakes that lead to these vulnerabilities. All testbench tests should be reviewed for potential errors, as a false pass / fail may negatively impact performance and code repair.

The complete list of CWE design rules can be found in the prompting directory of this repository.

## 3.6 Simulation
The generated testbench is then compiled and ran to test the given RTL design under the generated tests. If all tests pass, the given RTL module passes inspection, and all testing and analysis is completed. If one or more tests fail, the RTL design will then undergo a code repair (3.7).

## 3.7 Code Repair
Utilizing the results from the simulation, the RTL design will undergo code repair. The AI model is given the RTL design, all failed testbench tests, and the list of CWE design rules. The AI model is instructed to fix the module based off of the failed tests from the testbench simulation, while utilzing the CWE design rules as a guide for code repair. The AI model is also instructed to generate an updated testbench if changes to the RTL design were made that make it incompatible to the previously generated testbench (e.g. a new input). Once the fixed module (and potentially updated testbench) is generated, the simulation step is repeated (3.6) testing the repaired RTL design. Code repair was performed a maximum of 3 times; If the repaired module continued to fail the testbench after the 3rd iteration, the test was marked as a failure.

# 4. Results
Analysis reveals that the AI model demonstrated strong capabilities in understanding and reasoning about Verilog hardware designs and CWEs, but its performance varied depending on the task being performed.

The module classification produced favorable results. Across the evaluation, the AI correctly identified the functional type of the Verilog module in nearly all cases, with only one case of misclassifications observed.

The AI consistently performed well during the early stages of analysis. During asset identification, it was generally able to identify the primary security-relevant assets within a module and explain their intended functionality and importance. In many cases, the model correctly recognized the hardware vulnerability before the CWE-driven review was performed. Likewise, the AI accurately identified the behavior of modules and provided meaningful explanations of Project Dependency Graph (PDG) relationships and results from its analysis, showcasing its ability to reason about both the structural and behavioral aspects of the design.

The greatest weakness was observed during testbench generation. AI-generated testbenches frequently failed to validate the intended security properties of the design. Common issues included incorrect use of the Device Under Test (DUT), incomplete or ineffective test cases, and verification procedures that did not meaningfully determine whether the vulnerability was present or had been mitigated. In several instances, the generated testbenches also failed to properly reset the DUT between each test case, allowing the states from the previous tests to influence subsequent results, further reducing the reliability of the testbench.

Code repair produced mixed results. While the AI was often capable of generating syntactically correct patches that addressed the identified vulnerability, repairs occasionally modified the intended functionality of the original design. The reasoning from this stems from the lack of context given to the AI; The AI is given the module without any information about its intended behavior. Rather than implementing the minimal changes necessary to mitigate the weakness, the model sometimes introduced additional security mechanisms that were not required by the specification. For example, the AI occasionally added privilege-level inputs or access-control logic to modules whose intended functionality did not require privilege enforcement. These modifications improved security in a general sense but altered the original design requirements, highlighting the tendency of the model to favor security enhancements over preserving the original hardware behavior. In total, 27 of the 32 total tests conducted resulted in a pass; an 84% success rate.

### Non-Vulnerabilities
Of the 32 total modules, 5 Verilog modules did not contain vulnerabilities, and were tested to assess the AI's ability to distinguish secure designs from vulnerable ones. In these cases, the model showcassed a high false-positive rate. Across all five non-vulnerable modules tested, the AI identified at least one vulnerability, despite the modules being intentionally designed without security flaws.

Many of the reported vulnerabilities stemmed from the AI recommending security features that were unnecessary for the intended functionality of the module. For example, the model frequently suggested the addition of lock bits, write-once protections, or privilege-based access controls even when the design did not require these features. The AI often treated the absence of additional security mechanisms as a vulnerability.

The AI also showcased difficulty interpreting intended module behavior during testbench generation. In several cases, generated testbenches labeled intended functionality as incorrect, such as flagging the absence of data scrubbing after returning to a particular state even though this behavior was necessary for the module's opeartion. These incorrect assumptions resulted in failed test cases that the AI mistook for genuine security weaknesses. Because the failures originated from incorrect tests, code repair was not performed, as doing so would likely have altered the functionality of otherwise correct designs.

Consistent with the observations made for vulnerable modules, the quality of AI-generated testbenches remained a significant issue. Testbenches frequently contained ineffective or inappropriate security tests that did not accurately verify vulnerabilities, resulting in misleading testbench outcomes. Of the five non-vulnerable modules evaluated, three produced testbenches resulting in all tests passing. The remaining two testbenches were poorly designed and did not contain well-designed tests, which resulted in failed tests, further demonstrating that inaccurate verification was a major contributor to the AI's false-positive assessments.

# 5. Conclusion

# 6. References
<!--APA Format-->
Ahmad, B., Thakur, S., Tan, B., Karri, R., & Pearce, H. (2024). On Hardware Security Bug Code Fixes By Prompting Large Language Models. IEEE Transactions on Information Forensics and Security, 19, 1–1. https://doi.org/10.1109/tifs.2024.3374558

Alsaqer, S., Alajmi, S., Ahmad, I., & Alfailakawi, M. (2024). The potential of LLMs in hardware design. Journal of Engineering Research, 13(3). https://doi.org/10.1016/j.jer.2024.08.001

Knechtel, J., Sinanoglu, O., & Karri, R. (2026). LLMs for Secure Hardware Design and Related Problems: Opportunities and Challenges. In arXiv. https://arxiv.org/abs/2605.10807

Liu, H., Lu, Y., Wang, M., Yao, X., & Yu, B. (2026). LLM-Assisted Circuit Verification: A Comprehensive Survey. 2026 31st Asia and South Pacific Design Automation Conference (ASP-DAC), 439–446. https://doi.org/10.1109/asp-dac66049.2026.11420692

Long, X., Xia, Y., Kuang, L., Wan, Y., & Liu, Z. (2026). VerilogLAVD: LLM-Aided Pattern Generation for Verilog CWE Detection. ACL ARR 2026 January, 1, 28292–28308. https://aclanthology.org/2026.acl-long.1304.pdf

Mastora, M., & Sullivan, D. (2026). When Repairs Are Not Unique: Rethinking RTL Repair Benchmarks. Proceedings of the Great Lakes Symposium on VLSI 2026, 709–710. https://doi.org/10.1145/3787109.3815318

Meng, X., Ji, X., Zhang, G., He, J., Yang, D., Chen, F., Wang, J., Yu, C., Zhao, X., & Wu, J. (2025). Rtl design flaws revisited: a data-driven study of systematic bug patterns in Verilog code. The Journal of Supercomputing, 81(14). https://doi.org/10.1007/s11227-025-07811-9

MITRE. (2025, August 18). CWE - 2025 Most Important Hardware Weaknesses. https://cwe.mitre.org/topHW/archive/2025/2025_CWE_MIHW.html

Paria, S., & Bhunia, S. (2026). Harnessing the Power of LLMs for Enhancing Hardware Security. SN Computer Science, 7(2). https://doi.org/10.1007/s42979-026-04799-8

Qi, H., Du, Y., Zhang, L., Liew, S. C., Chen, K., & Du, Y. (2026, April). Verirag: A retrieval-augmented framework for automated rtl testability repair. In 2026 27th International Symposium on Quality Electronic Design (ISQED) (pp. 1-8). IEEE.

## Unused References

Cheung, B. (2025, December). Abstraction of Thought Makes AI Better Reasoners. Benny’s Mind Hack. https://bennycheung.github.io/abstraction-of-thought-makes-ai-better-reasoners

Mell, P., & Bojanova, I. (2024). Hardware Security Failure Scenarios: Potential Hardware Weaknesses. In NIST Computer Security Research Center. National Institute of Standards and Technology. https://doi.org/10.6028/nist.ir.8517

Mukherjee, R., & Chakraborty, R. S. (2026). Detecting Hardware Trojans in High-Level Synthesis-Generated RTL using Large Language Models. ACM Transactions on Design Automation of Electronic Systems. https://doi.org/10.1145/3795509


