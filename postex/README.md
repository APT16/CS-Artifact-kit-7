# Postex Kit

The Postex kit allows users to build upon Cobalt Strike's existing job 
architecture to create their own long running postex tasks.

## Prerequisites:

Required:

* An x64 Windows 10/11 development machine (without a security solution).
* Visual Studio Community/Pro/Enterprise 2022 (Desktop Development with C++ installed).
* Cobalt Strike 4.10.

## Creating A DLL

To start from the beginning, and create a new DLL:
* Open the `postex.sln` solution.
* Export a template:
  * Select Project->Export Template.
  * Use the wizard to create a template of the `postex` project.
  * Save the template to your local file system.
* Create a new project 
  * Select File->New->Project
  * Search for the template created above.
  * Give project a name and under "Solution" make sure to select "Add to Solution".
* Begin development in `PostexMain()`

## Executing A DLL

The Postex kit works in combination with the `execute-dll` command in the Beacon console
and/or the `beacon_execute_postex_job()` Aggressor function.

### Execute-DLL

`execute-dll` operates in a similar fashion to other beacon console commands. This command
takes the Dll passed in by the operator, prepends a postex loader and executes it. Output
is then returned to the user via a named pipe. The postex job can be seen in the `jobs` output
and killed via 'jobkill [jid]'.

It is possible to pass optional arguments to the DLL via the `execute-dll` command. These 
arguments are copied into a separate memory allocation, and a pointer to the buffer is
passed to the postex DLL by the postex loader. An example of this can be seen in the postex
example DLL provided in the kit.

### beacon_execute_postex_job()

`beacon_execute_postex_job()` is an Aggressor function which provides a lot more flexibility.
This function works similarly to `execute-dll`, however, it also provides an opportunity to
use Beacon Object File (BOF) style arguments via `bof_pack()`. These can then be used with the
familiar Beacon Data Parsing/Format APIs that can be found in `beacon.h`.

Note: It is also possible to utilize Aggressor Script to "stomp" arguments in to the postex DLL
directly.

## Bi-directional Communication

It is possible to communicate with a postex job via its named pipe using the `bjob_send_data()`
Aggressor function. This can be used in combination with `BeaconInputAvailable()` and
`BeaconInputRead()` in the postex DLL itself. `BeaconInputAvailable` checks if there is data
available on the pipe and `BeaconInputRead` can be used to read the data. An example of this
approach can be seen in the example DLL provided in the kit.

Note: The Postex Kit DLL is required to read any data on the pipe before Beacon is able
to send any more data to it.

## Modifications

You're encouraged to make modifications to this code and use it in your
engagements. Do not redistribute this source code. It is not open source. It
is provided as a benefit to licensed Cobalt Strike users.

## License

This code is subject to the end user license agreement for Cobalt Strike. The
complete license agreement is at:

https://www.cobaltstrike.com/license