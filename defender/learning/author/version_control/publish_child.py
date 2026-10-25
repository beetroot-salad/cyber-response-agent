"""The launch-time publish child's process entry (`python -m` this module): see `publish`."""
import sys

from defender.learning.author.version_control.publish import publish_child_main

if __name__ == "__main__":
    from defender._log import configure_from_env

    configure_from_env()
    # The launcher kills this child's whole process group when it ends (O-BUDGET): its network
    # git joins that group, so no fetch outlives the child, a SIGKILL included. Here, at the
    # process entry only, never where an in-process caller would inherit it.
    from defender import _git

    _git.join_caller_group()
    sys.exit(publish_child_main(sys.argv[1:]))
