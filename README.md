# KDStab
This is a Beacon Object File combined implementation of Yaxser's Backstab and pwn1sher's KillDefender for use with Cobalt Strike. 


Additional work would alter the BeaconPrint statements to utilize something neater like Trustedsec's method.

# Changes
A few changes were made to the code during the port of the original:

  1. The ProcExp driver is no longer stored/loaded as a resource, it is a hardcoded byte array in resource.c

  2. There were several memory leaks in the original code that I found and resolved

# To Compile:
After initially trying to port this tool in Visual Studio, I ended up porting this on Linux using mingw-gcc.  I have not tried to compile for x86, or using VS (where there will be issues due to gcc/VS-only C issues).

To compile using gcc:
````
x86_64-w64-mingw32-gcc -o backstab.x64.o -Os -c main.c -DBOF -D_UNICODE
````

<ins>Make sure that you have updated your mingw to the latest version! I had issues where my version had outdated header files, however the latest version's header files are correct.</ins>


# Credits
  1. First and foremost, Yaxser and his cool tool: https://github.com/Yaxser/Backstab

  2. Trustedsec for his CS-Situational-Awareness-BOF repo which was a huge help during the porting process.  I used snippets of his code in this project and I highly recommend anyone who is getting into writing BOF's check the repo out: https://github.com/trustedsec/CS-Situational-Awareness-BOF
