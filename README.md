# Shimada

## Project Overview
This project focused on developing offensive security automation skills by building a Python tool to enumerate and exploit Active Directory. Instead of relying on existing tools, I created a custom port scanner using Python’s socket and threading libraries (200 threads) to practice raw socket programming. The script identifies common services such as SMB, HTTP, Kerberos, and LDAP, then provides options for enumeration and exploitation. Output is saved to files to reduce console clutter. The tool was tested against the WaterExecution VulnAD lab, with plans to expand functionality (e.g., automated SMB share searching and modular exploit options).

## Key Achievements
- Developed a custom multithreaded port scanner from scratch in Python.  
- Automated detection and enumeration of common AD-related services.  
- Implemented structured output handling for cleaner reporting.  
- Validated tool functionality against a vulnerable AD environment (VulnAD).  

## Technical Skills Demonstrated
- Offensive Python development and automation.  
- Active Directory enumeration and exploitation concepts.  
- Proficiency with Python libraries: `socket`, `threading`, `subprocess`, `re`, `sys`.  
- Building, testing, and refining scripts in a controlled lab environment.  

## Process Summary
1. Built a custom multithreaded port scanner in Python.  
2. Verified open services (SMB, HTTP, Kerberos, LDAP, etc.).  
3. Implemented logic to allow user-driven enumeration and exploitation.  
4. Directed scan and enumeration results into structured output files.  
5. Tested the script against the WaterExecution VulnAD environment.  
6. Planned improvements such as automated SMB share enumeration and modular exploit expansion.  

## Outcome
This project strengthened my Python programming skills, reinforced knowledge of AD attack surfaces, and provided experience creating custom tools for red-team style offensive operations.


## Evidence 

**Ref 1: AD Environment**  
<img width="1920" height="1057" alt="image" src="https://github.com/user-attachments/assets/9fd84b7c-3356-4630-8fed-9946f07708d6" />

**Ref 2: Script Output**  
<img width="1919" height="893" alt="image" src="https://github.com/user-attachments/assets/9d77970b-1e2c-4b05-b8a4-89920bff2456" />  
<img width="1907" height="827" alt="image" src="https://github.com/user-attachments/assets/5ef129de-118c-47d7-b328-de270a06dbff" />  
<img width="1912" height="475" alt="image" src="https://github.com/user-attachments/assets/32b1009c-1aca-4d22-af7d-05e7c2f324b8" />  

**Ref 3: Output Files**  
<img width="1908" height="407" alt="image" src="https://github.com/user-attachments/assets/50112a78-b99c-4222-8a83-04deefad7365" />  
<img width="1910" height="710" alt="image" src="https://github.com/user-attachments/assets/062129ae-4625-41f8-9452-22a845dbd760" />  










