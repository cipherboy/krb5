#!/usr/bin/python
from k5test import *

realm = K5Realm()

# Run gss_create_sec_context interop tests.
realm.run(['./t_create_exchange', 'p:' + realm.host_princ])

realm.stop()
success('GSSAPI subtests')
