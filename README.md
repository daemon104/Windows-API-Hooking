# Windows-API-Hooking
Windows API Hooking is a technique by which we can intercept and modify the behavior and flow of API calls. The main function of this technique is ReadProcessMemory and WriteProcessMemory, set up the hook by following these steps below:

* First, select the target function to be hooked (called TargetFuncAddress), get it's memory address with LoadLibraryA and GetProcAddress
* Next, read it's first 6 bytes in memory and save it to a buffer, these bytes will be used to unhooking later
* Next, create a proxy function (aka hooked function) and retrive it's address (called HookedFuncAddress). This proxy function can be defined by us, so it might be a malicious function.
* Then, create a patch contains 6 bytes assembly instruction: ```push <HookedFuncAddress>; ret```
* Finally, overwrite the first 6 bytes in memory of target function with the patch using WriteProcessMemory, this will cause the function to execute the push instruction to push the address of proxy function to the stack and then jump to it, so the flow of API calls is modified

After set up the hook , we call the API function 2 times, example with target function is MessageBoxA, here is the workflow: 

```Call MessageBoxA with value "Origin"``` -> ```Set up the hook``` -> ``` Call MessageBoxA again with the same value "Origin"```

So in the second time called the MessageBoxA, our proxy function will return a modified value from "Origin" to "Success"

Usage: ```API-Hooking.exe```
