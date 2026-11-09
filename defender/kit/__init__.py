"""What crosses the adapter boundary (#1080), and the clients that cross it: the faults adapters
raise, the verb decorator and its marks, the call context as an adapter sees it, the settings
value types, the shared transport every adapter reaches its system with (through the credential
proxy, #1391), and the clients of the deployment's own services that transport is built on. Both
the runtime and the adapters import it; it imports nothing else from `defender`, so #1172 can
lift it out whole."""
