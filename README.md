# KDStab
This is a Beacon Object File combined implementation of Yaxser's Backstab and pwn1sher's KillDefender for use with Cobalt Strike. 
![image](https://user-images.githubusercontent.com/91164728/157600560-ebc12f11-a74d-47aa-a6a4-9636e81bb24b.png)


# Background
I came across  pwn1sher's KillDefender shortly after it's release and thought it was awesome; in addition to rendering MsMpEng.exe(Defender) useless, it leaves the process running which seems desirable from an OPSEC standpoint (in addition to the fact that the default behavior of the WinDefend service is the restart MsMpEng.exe on failure- something that will be useful later). 

While blinding Defender is awesome for an engagement, as professionals we are responsible for restoring client's assets to the state in which we found them; plus, we don't really want to leave their systems exposed for other actors because we Kill(ed)Defender.  

The trouble is that one cannot "restore" MsMpEng.exe to it's working state easily.  KillDefender works by stripping the target process of it's privileges (SeDebugPrivilege, etc...) and settings it's token integrity to untrusted.  One cannot just "re-escalate" the token to System and restore the privileges, the process must be killed and a fresh instance started. Of course MsMpEng.exe is also a PsProtectedSignerAntimalware-Light process, so even as System we cannot just end the process. Frustratingly the TrustedInstaller group was removed from MsMpEng.exe recently (you can find some other research about this) rendering that technique for truly killing the MsMpEng.exe process (or the WinDefend service) which has been around for many years ineffective.

Armed with this problem I started looking around and quickly found Yaxser's Backstab.  Backstab is able to kill PPL protected processes by leveraging ProcExp's driver; this is a Microsoft signed driver from sysinternals which works in our favor.  Backstab does perform some OPSEC-unsafe actions; it drops the driver to disk and creates reg keys.  However, if Defender is already blind... :). 

I set out to port both of these tools to BOF format so that they might be used through a Cobalt Strike Beacon without needing to drop them to disk (the original Backstab binary was blocked on runtime by Defender).

I am both new to C/C++ as well as to writing BOF's and I learned a lot during the process.  You will find some inconsistencies in the code (like how Backstab_bof is written and compiled on linux using gcc and KillDefender_bof is written and compiled in Visual Studio) due to me learning during the creation process, but I have done a fair amount of testing to ensure functionality and I also built quite a few rails into the aggressor script to ensure proper usage and input to the BOF's.  I hope that you find this tool useful.

# Changes and Programming Notes:

A few notable changes were made to the source code of the tools and certain programattic choices were made that will be mentioned here:

  1. The ProcExp driver is no longer stored/loaded as a resource, it is a hardcoded byte array in backstab_src/resource.c

  2. There were several memory leaks in the original Backstab code that I found and resolved

  3. The KillDefender POC fails when the user is not System; I added a snippet to enumerate the running user and get system through impersonation of Winlogon's token if need be.

  4. Backstab uses enough different API's and C calls that CobaltStrike wasn't able to manage resolving all of the dynamic function resolution- trustedsec to the rescue! I implemented their dynamic function resolution to supplement CS's so that all of the necessary API's could be called.

  5. The original Backstab has several switch/case statements that caused problems during the port, so they were replaced with if/else statements.  Additionally pretty much all global variables were eliminated for similar reasons.

  6. I know it is odd that one tool was written for Visual Studio and the other for GCC; this is a casualty of me struggling to successfully port these and having lots of growing pains along the way.  Future tools should hopefully benefit from a lot of the lessions that I learned along the road here.  


# To Compile:
I have not tried to compile either tool for x86; if you really need a version of this for that I will leave it to you to figure it out.

To compile the Backstab_bof using gcc:
````
x86_64-w64-mingw32-gcc -o backstab.x64.o -Os -c main.c -DBOF -D_UNICODE
````
<ins>Make sure that you have updated your mingw to the latest version! I had issues where my version had outdated header files, however the latest version's header files are correct.</ins>

To compile the KillDefender_bof using x64 Native command prompt:
````
cl.exe /c /GS- /TP killdefender_bof.cpp /FoKillDefender.x64.o
````

# Credits
  1. First and foremost, Yaxser and his cool tool: https://github.com/Yaxser/Backstab

  2. Trustedsec for his CS-Situational-Awareness-BOF repo which was a huge help during the porting process.  I used snippets of his code in this project and I highly recommend anyone who is getting into writing BOF's check the repo out: https://github.com/trustedsec/CS-Situational-Awareness-BOF
