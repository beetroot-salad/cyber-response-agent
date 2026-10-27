#!/bin/sh
# Declare the decrypt-only key only once a rotation has left one behind: Kibana refuses to start
# when the list is empty-stringed or holds the current key. The appended line is the ${VAR}
# reference, not the key, so the key stays out of the file and off every command line.
set -eu
cfg=/usr/share/kibana/config/kibana.yml
if [ -n "${KBN_ENCRYPTION_KEY_PREVIOUS:-}" ] && [ "${KBN_ENCRYPTION_KEY_PREVIOUS}" != "${KBN_ENCRYPTION_KEY}" ] \
    && ! grep -q decryptionOnlyKeys "$cfg"; then
    echo 'xpack.encryptedSavedObjects.keyRotation.decryptionOnlyKeys: [ "${KBN_ENCRYPTION_KEY_PREVIOUS}" ]' >> "$cfg"
fi
exec "$@"
