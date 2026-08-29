"""Test-package initialisation: isolate ASF host state for the whole process.

``RepoPaths`` resolves ``${XDG_STATE_HOME:-~/.local/state}`` at construction
time. Individual fixtures patch the variable, but any ``RepoPaths`` built
outside such a patch (module-level helpers, service internals) would silently
write real session state under the developer's home. Setting the variable once,
before any test module imports ``asf``, makes that impossible by construction.

``tests/run.sh`` exports its own value first; this guard only fills the gap
when the suite is invoked directly via ``python3 -m unittest``.
"""

import atexit
import os
import shutil
import tempfile

if not os.environ.get("ASF_TEST_STATE_GUARD"):
    _state_home = tempfile.mkdtemp(prefix="asf-test-state-")
    os.environ["XDG_STATE_HOME"] = _state_home
    os.environ["ASF_TEST_STATE_GUARD"] = _state_home
    atexit.register(shutil.rmtree, _state_home, True)
