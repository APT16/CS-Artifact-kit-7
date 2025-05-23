# Beacon User Data Loader Example

Beacon User Data (BUD) is a C-structure that allows Reflective Loaders to pass additional data to Beacons.
This loader example serves as a demonstration of the BUD feature originally introduced in CS 4.9.

**Note:** This loader uses the "Double Pulsar" approach to loading. As a result, it is important to increase the "stage size" when generating artifacts via the Arsenal kit.

## Quick Start Guide

To get started, use the instructions provided below.

### Debug Build

To start Debugging:
* Export a RAW Beacon payload from the teamserver (our Debug DLL).
* Add the DLL to the project - `py.exe .\udrl.py xxd <path\to\beacon_x64.bin> .\library\DebugDLL.x64.h`.
* Start the Visual Studio Debugger (make sure to right-click bud-loader in the
Solution Explorer->Set As Startup Project).

### Release Build

To use the Release build:
* Compile the `Release` build.
* Test the loader (the below example is for x64):
	* `py.exe .\udrl.py prepend-udrl <path\to\beacon_x64.bin> bin\bud-loader\Release\x64\bud-loader.x64.exe`
* Load (`bin/bud-loader/prepend-udrl.cna`) to Cobalt Strike.
* Export a Beacon payload.
  * Modify "stage size" if using Cobalt Strike's default shellcode runners/the artifact kit.

**Note:** Make sure to use the 32-bit version of Python when testing the x86 builds!

## Modifications

You're encouraged to make modifications to this code and use them in your
engagements. Do not redistribute this source code. It is not open source. It
is provided as a benefit to licensed Cobalt Strike users.

## License

This code is subject to the end user license agreement for Cobalt Strike. The
complete license agreement is at:

https://www.cobaltstrike.com/license

This code is subject to the license for the Reflective loader project by
Stephen Fewer. The complete license is at:

https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/LICENSE.txt
