# Hardware-Vulnerabilities

# Abstract

Verilog is a Hardware Description Language (HDL) that allows circuits to be represented as a programming language. Like software-based programming languages, hardware-based HDLs are prone to bugs that jeopardize the security of the circuit, favoring malicious actors. However, a key difference is that hardware vulnerabilities cannot be patched after production, as the circuits are permanently engrained in silicon. These vulnerabilities, known as Common Weakness Enumerations (CWEs) allow for easy grouping and identification, with most hardware related CWEs involving improper access control, exposed sensitive data, and unintended privilege escalation. As a result, we have developed a methodology identify and minimize the occurrence of CWEs with the use of a Learning Language Model (LLM).
<!-- Add more to this section later. -->
# Introduction
Due to the constant improvement and evolution of software security, computers have become increasingly difficult for hackers to exfiltrate personal information from. However, even if the software on a device is completely secure, its hardware can still expose important data. As a result, MITRE has created a list called Common Weakness Enumeration (CWE), contain different groups of these vulnerabilities on a device's software or hardware based on its design. These vulnerabilities are also caled Common Weakness Enumerations (CWEs). In particular, hardware-based CWEs, represented in the hardware description language (HDL) Verilog, can lead to unauthorized data exposure, priviledge escalation, and other issues if not properly checked. 
# Motivation
<!-- It's important to find CWEs early before they become an issue later. -->
<!--LLMs have an increasing amount of relevance in the field of cybersecurity and can be used to simplify the task. -->
# Methodology

<img width="1040" height="588" alt="Flow" src="https://github.com/user-attachments/assets/c60b714a-4af1-452e-b5ad-e9e287552014" />


### Identify Module


### Identify Assets and Behavior



### CWE-Driven Manual Review



### Test Benches for CWEs


##### Testbench Rules


### Evaluate Needs



##### CWE-Based Design Rules




# Results

# Conclusion

# References
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
