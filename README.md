# Hardware-Vulnerabilities

# Abstract

Verilog is a Hardware Description Language (HDL) that allows circuits to be represented as a programming language. Like software-based programming languages, hardware-based HDLs are prone to bugs that jeopardize the security of the circuit, favoring malicious actors. However, a key difference is that hardware vulnerabilities cannot be patched after production, as the circuits are permanently engrained in silicon. These vulnerabilities, known as Common Weakness Enumerations (CWEs) allow for easy grouping and identification, with most hardware related CWEs involving improper access control, exposed sensitive data, and unintended privilege escalation. As a result, we have developed a methodology identify and minimize the occurrence of CWEs with the use of a Learning Language Model (LLM).
<!-- Add more to this section later. -->
# Introduction
Due to the constant improvement and evolution of software security, computers have become increasingly difficult for hackers to exfiltrate personal information from. However, even if the software on a device is completely secure, its hardware can still expose important data. As a result, MITRE has created a list called Common Weakness Enumeration (CWE), contain different groups of these vulnerabilities on a device's software or hardware based on its design. These vulnerabilities are also caled CWEs. In particular, hardware-based CWEs, represented in the hardware description language (HDL) Verilog, can lead to unauthorized data exposure, priviledge escalation, and other issues if not properly checked. 
# Motivation

# Methodology

<img width="1040" height="588" alt="Flow" src="https://github.com/user-attachments/assets/c60b714a-4af1-452e-b5ad-e9e287552014" />


### Identify Module



### Identify Assets and Behavior



### CWE-Driven Manual Review



### Test Benches for CWEs



### Evaluate Needs



##### CWE-Based Design Rules





# Results

# Conclusion

