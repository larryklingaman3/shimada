# shimada
Python script to automatically enumerate and exploit Active Directory

**Overview**

The goal of this project was to further develop my offensive python skills by writing a script to automatically enumerate and exploit Active Directory. Since this is not meant to be used on a production enviornment, I wrote a port scanner from scratch that uses 200 threads instead of just using nmap T5 in order to practice using the Python socket module. From the output of the port scan, the script verifies if common services such as SMB, HTTP, Kerberos, LDAP, etc are open and gives the user the choice to enumerate/exploit. The script saves output to designated files in order to reduce visual clutter from the output. I wrote and tested the script against the WaterExecution VulnAD github script. In the future, I would like to re-write this script as my red teaming skills advance and I am able to automate more of the process. In the near futute for this script I would like to add functionality to automatically search inside of SMB shares and list any files found in the output of the script. 



**Skills Learned**

- Active Directory enumeration and exploitation tactics
- Enhancing my proficeicy of Python libraries such as socket, threading, re, sys, and subprocess

**Active Directory Enviornment and Code Output**
_Ref 1: AD Enviornment_
<img width="1920" height="1057" alt="image" src="https://github.com/user-attachments/assets/9fd84b7c-3356-4630-8fed-9946f07708d6" />

_Ref 2: Script Output_
<img width="1919" height="893" alt="image" src="https://github.com/user-attachments/assets/9d77970b-1e2c-4b05-b8a4-89920bff2456" />
<img width="1907" height="827" alt="image" src="https://github.com/user-attachments/assets/5ef129de-118c-47d7-b328-de270a06dbff" />
<img width="1912" height="475" alt="image" src="https://github.com/user-attachments/assets/32b1009c-1aca-4d22-af7d-05e7c2f324b8" />

_Ref 3: Output Files_
<img width="1908" height="407" alt="image" src="https://github.com/user-attachments/assets/50112a78-b99c-4222-8a83-04deefad7365" />
<img width="1910" height="710" alt="image" src="https://github.com/user-attachments/assets/062129ae-4625-41f8-9452-22a845dbd760" />







