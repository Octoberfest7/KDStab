# KDStab
This is a Beacon Object File combined implementation of Yaxser's Backstab and pwn1sher's KillDefender for use with Cobalt Strike. 

![image](https://user-images.githubusercontent.com/91164728/157608940-2dc938e5-fa50-41b0-87b7-f722644a805f.png)

# Introduction
KDStab is a post-explotiation tool to defeat Windows Defender (in theory it could work for other solutions as well but have not tested) so that other post-ex tools may be used without as much fear of detection. It leverages Backstab and KillDefender in order to accomplish this, both of which are called when appropriate by the kdstab Cobalt Strike command.

KDStab has been tested successfully on x64 Windows 10, Windows 11, and Server 2019. 

KDStab requires Administrator or System level access.

Primary functions:

  1. Enumerate the integrity of a process
  
  2. Strip a process of its privileges and set its integrity to Untrusted
  
  3. Kill a PPL protected process
  
  4. List the handles for a PPL protected process
  
  5. Close a specific handle for a PPL protected process

# Examples
Check the integrity level of a process

![image](https://user-images.githubusercontent.com/91164728/157605672-d4a491e9-c8a8-4215-aef3-eaa99deb30d6.png)

Strip a process of its privileges and set its token to Untrusted

![image](https://user-images.githubusercontent.com/91164728/157605903-f2df0b50-d233-45b7-b092-6fbb6022d95c.png)

Result of /STRIP command

![image](https://user-images.githubusercontent.com/91164728/157606113-36256c63-59ef-4e15-8f18-ef3dc7ecc34f.png)

Kill a PPL protected process

![image](https://user-images.githubusercontent.com/91164728/157605876-4572bf6e-d1f2-4c1b-ac23-d5f10f863e8b.png)

# Background
I came across  pwn1sher's KillDefender shortly after it's release and thought it was awesome; in addition to rendering MsMpEng.exe(Defender) useless, it leaves the process running which seems desirable from an OPSEC standpoint (in addition to the fact that the default behavior of the WinDefend service is to restart MsMpEng.exe on failure- something that will be useful later). 

While blinding Defender is awesome for an engagement, as professionals we are responsible for restoring client's assets to the state in which we found them; plus, we don't really want to leave their systems exposed for other actors because we Kill(ed)Defender.  

The trouble is that it is tough to "restore" MsMpEng.exe to its working state.  KillDefender works by stripping the target process of its privileges (SeDebugPrivilege, etc...) and setting its token integrity to untrusted.  One cannot just "re-escalate" the token to System and restore the privileges, the process must be killed and a fresh instance started. Of course MsMpEng.exe is also a PsProtectedSignerAntimalware-Light process, so even as System we cannot just end the process. Frustratingly the TrustedInstaller group was removed from MsMpEng.exe recently (you can find some other research about this) rendering that technique for truly killing the MsMpEng.exe process (or the WinDefend service) which has been around for many years ineffective. All this being the case, the only seemingly viable option is to restart the machine which could cause a client problems if we start talking about servers and DC's.

Armed with this problem I started looking around and quickly found Yaxser's Backstab.  Backstab is able to kill PPL protected processes by leveraging ProcExp's driver; this is a Microsoft signed driver from sysinternals which works in our favor.  Backstab does perform some OPSEC-unsafe actions; it drops the driver to disk and creates reg keys.  However, if Defender is already blind... :). 

I set out to port both of these tools to BOF format so that they might be used through a Cobalt Strike Beacon without needing to drop them to disk (the original Backstab binary was blocked on runtime by Defender).

I am both new to C/C++ as well as to writing BOF's and I learned a lot during the process.  You will find some inconsistencies in the code (like how Backstab_bof is written and compiled on linux using gcc and KillDefender_bof is written and compiled in Visual Studio) due to me learning during the creation process, but I have done a fair amount of testing to ensure functionality and I also built quite a few rails into the aggressor script to ensure proper usage and input to the BOF's.  I hope that you find this tool useful.

# Changes and Programming Notes:

A few notable changes were made to the source code of the tools and certain programmatic choices were made that will be mentioned here:

  1. The ProcExp driver is no longer stored/loaded as a resource, it is a hardcoded byte array in backstab_src/resource.c

  2. There were several memory leaks in the original Backstab code that I found and resolved

  3. The KillDefender POC fails when the user is not System; I added a snippet to enumerate the running user and get system through impersonation of Winlogon's token if need be.

  4. KillDefender was modified to allow users to specify which process to target; additionally a "Check" mode was added to enumerate the integrity level of a process (which can confirm that a process was successfully stripped of its privileges and integrity).

  5. Backstab uses enough different API's and C calls that Cobalt Strike wasn't able to manage resolving all of the dynamic function resolution- trustedsec to the rescue! I implemented their dynamic function resolution to supplement CS's so that all of the necessary API's could be called.

  6. The original Backstab has several switch/case statements that caused problems during the port, so they were replaced with if/else statements.  Additionally pretty much all global variables were eliminated for similar reasons.

  7. I know it is odd that one tool was written for Visual Studio and the other for GCC; this is a casualty of me struggling to successfully port these and having lots of growing pains along the way.  Future tools should hopefully benefit from a lot of the lessons that I learned along the road here.

  8. Both KillDefender_bof and Backstab_bof exist as standalone repos. NOTE THAT CODE IS DIFFERENT BETWEEN THE STANDALONE REPOS AND THIS TOOL. This was done in order to make them more flexible and able to integrate into a single package.

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
  1. Yaxser and his Backstab tool: https://github.com/Yaxser/Backstab

  2. pwn1sher and his KillDefender tool: https://github.com/pwn1sher/KillDefender

  3. Trustedsec for his CS-Situational-Awareness-BOF repo which was a huge help during the porting process.  I used snippets of his code in this project and I highly recommend anyone who is getting into writing BOF's check the repo out: https://github.com/trustedsec/CS-Situational-Awareness-BOF
