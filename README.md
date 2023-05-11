# BYOVD Demo for CYBERSEC 2023

## Description
This demo is a presentation at the CYBERSEC 2023 in Taiwan. The presentation showcases the abuse of RTCore64.sys from MSI and the nullification of the DSE flag to load a malicious unsigned driver. The presentation also demonstrates an attack on 360 Total Security by nulling out its ObRegisterCallbacks and notify callbacks, enabling the execution of any malicious behavior on the processes of 360 Total Security.

## Info
* Session: https://cyber.ithome.com.tw/2023/session-page/1799
* Demo Video: https://www.youtube.com/watch?v=dLEHRmdY33c

## Environment
* Windows 10 1909
* Visual Studio 2017
* 360 Total Security 10.8.0.1456

## Usage
1. Install 360 Total Security 10.8.0.1456
2. Put BYOVD.exe, Malicious.sys, and RTCore64.sys to the same directory.
3. Execute BYOVD.exe with Administrator, and 360 Total Security is expected to be killed.

## Reference
* find DSE flag: https://github.com/hfiref0x/DSEFix
* abusing RTCore64.sys (CVE-2019-16098) and null out notify callbacks: https://github.com/br-sn/CheekyBlinder