#!/usr/bin/env python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""Assert the plaintext fallback warning is suppressed on a real platform-managed agent.

Meant to be run on an Azure Pipelines or GitHub Actions agent, and needs no sign-in: the warning is
decided by build_persistence and warn_if_encryption_unavailable alone.

The unit tests mock the environment, so they cannot show that an agent really sets TF_BUILD or
GITHUB_ACTIONS. This runs the same code against whatever the agent actually provides, then repeats
it with those variables removed, so a pass means the gate is what silenced the warning and not a
fallback that never happened.
"""

import logging
import os
import sys
import tempfile

from azure.cli.core.auth import persistence
from azure.cli.core.util import in_ci, in_managed_environment

CI_VARIABLES = ('TF_BUILD', 'GITHUB_ACTIONS', 'CI')


def _collect(level):
    """Capture messages the persistence logger emits at one level."""
    messages = []
    handler = logging.Handler()
    handler.emit = lambda record: messages.append(record.getMessage())
    handler.setLevel(level)
    return messages, handler


def _fall_back():
    """Ask for encryption on a machine with no usable keyring, and return the debug log."""
    debug, handler = _collect(logging.DEBUG)
    persistence.logger.addHandler(handler)
    persistence.logger.setLevel(logging.DEBUG)
    try:
        persistence._encryption_fallback = False  # pylint: disable=protected-access
        with tempfile.TemporaryDirectory() as directory:
            store = persistence.build_persistence(directory + '/probe', True, type='Token cache')
    finally:
        persistence.logger.removeHandler(handler)
    return store, debug


def _warnings_from_sign_in():
    warnings, handler = _collect(logging.WARNING)
    persistence.logger.addHandler(handler)
    try:
        persistence.warn_if_encryption_unavailable()
    finally:
        persistence.logger.removeHandler(handler)
    return [message for message in warnings if message == persistence.ENCRYPTION_FALLBACK_WARNING]


def main():
    seen = {name: os.environ.get(name) for name in CI_VARIABLES}
    print('agent environment: ' + ', '.join(
        f'{name}={value!r}' if value is not None else f'{name}=<unset>' for name, value in seen.items()))
    print(f'in_ci()={in_ci()}, in_managed_environment()={in_managed_environment()}')

    failures = []
    if not in_ci():
        failures.append('this agent sets none of the variables in_ci() looks for, so the gate this '
                        'checks would never apply here')
    if not in_managed_environment():
        failures.append('in_managed_environment() is False on a CI agent')

    # The fallback itself has to happen, or there would be no warning to suppress and a pass would
    # mean nothing.
    store, debug = _fall_back()
    if store.is_encrypted:
        failures.append('the persistence reports itself as encrypted, so there was no fallback to '
                        'observe on this agent')
    if not isinstance(store, persistence.FilePersistence):
        failures.append(f'expected a plaintext FilePersistence, got {type(store).__name__}')
    if not persistence._encryption_fallback:  # pylint: disable=protected-access
        failures.append('the fallback was not recorded')
    if not any('Failed to initialize LibsecretPersistence' in message for message in debug):
        failures.append('the reason libsecret was unusable never reached the debug log')

    if _warnings_from_sign_in():
        failures.append('sign-in warned about plaintext storage on a platform-managed agent, where '
                        'the user cannot act on it')

    # Same process, same fallback, with only the CI variables taken away. Without this a silent
    # warning path would pass just as happily as a working gate.
    removed = {name: os.environ.pop(name) for name in CI_VARIABLES if name in os.environ}
    try:
        if not _warnings_from_sign_in():
            failures.append(f'with {", ".join(removed)} removed the sign-in still said nothing, so '
                            'the silence above was not the gate')
    finally:
        os.environ.update(removed)

    for failure in failures:
        print(f'##vso[task.logissue type=error]{failure}')
    if failures:
        return 1

    print('the fallback happened, was explained in the debug log, and the warning was suppressed '
          'only because this is a platform-managed agent')
    return 0


if __name__ == '__main__':
    sys.exit(main())
