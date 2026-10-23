"""The launch-time publish child's process entry (`python -m` this module): see `publish`."""
import sys

from defender.learning.author.version_control.publish import publish_child_main

if __name__ == "__main__":
    from defender._log import configure_from_env

    configure_from_env()
    sys.exit(publish_child_main(sys.argv[1:]))
