# ExportProxy
A simple, small, easy to use and highly modifiable library for mass redirecting module exports without hardcoding names or arguments, to your own module, supporting both dynamic and static importing.

The size is about 30kb or so and it only requires two headers.
I use MinHook for hooking GetProcAddress to support dynamic imports.

# How it works:
Dynamic (GetProcAddress Support:
I use MinHook to hooking GetProcAddress to support dynamic imports by checking whether the function is in a target module, if so, replace the call to our callback.

Static (Linking against the function):
Parse the NT Headers and replace all function imports in the target dlls to our own address.

# **Why did I make this?**
I frequently use DLL Proxying on modules with huge amounts of exports and having to use IDA to get argument types and then export them one by one in my code, fix types, and then debug crashes due to type conflicts or internal usage was really annoying.
