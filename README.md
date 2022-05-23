[TryHackMe | Biblioteca](https://tryhackme.com/room/biblioteca)

`Shhh. Be very very quiet, no shouting inside the biblioteca.`

## Task 1 What is the user and root flag? 
```
root@ip-10-10-xxx-xxx:~# nmap -sV -O -Pn 10.10.23.205

Starting Nmap 7.60 ( https://nmap.org ) at 2022-05-23 17:19 BST
Nmap scan report for ip-10-10-23-205.eu-west-1.compute.internal (10.10.23.205)
Host is up (0.00063s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
MAC Address: 02:C1:B4:F5:C1:F7 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=5/23%OT=22%CT=1%CU=32718%PV=Y%DS=1%DC=D%G=Y%M=02C1B4%T
OS:M=628BB439%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=104%TI=Z%CI=Z%TS=A
OS:)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5
OS:=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W
OS:6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=
OS:0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U
OS:1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DF
OS:I=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.55 seconds
```
