"""What crosses the adapter boundary (#1080): the faults adapters raise, the verb decorator and
its marks, the call context as an adapter sees it, and the settings value types. Both the
runtime and the adapters import it; it imports nothing else from `defender`, so #1172 can lift
it out whole."""
