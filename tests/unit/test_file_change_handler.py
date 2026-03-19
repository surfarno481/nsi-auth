#  Copyright 2026 SURF.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from pathlib import Path
from unittest.mock import MagicMock

from flask import Flask
from watchdog.events import FileModifiedEvent


def test_file_change_handler_calls_callback_on_init(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that FileChangeHandler calls callback during initialization."""
    from nsi_auth import FileChangeHandler

    callback = MagicMock()
    FileChangeHandler(allowed_client_dn, callback)

    callback.assert_not_called()  # __init__ calls load_allowed_client_dn directly, not callback


def test_file_change_handler_on_modified_matching_file(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that on_modified calls callback when the watched file is modified."""
    from nsi_auth import FileChangeHandler

    callback = MagicMock()
    handler = FileChangeHandler(allowed_client_dn, callback)

    event = FileModifiedEvent(str(allowed_client_dn))
    handler.on_modified(event)

    callback.assert_called_once_with(allowed_client_dn)


def test_file_change_handler_on_modified_different_file(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that on_modified ignores events for other files."""
    from nsi_auth import FileChangeHandler

    callback = MagicMock()
    handler = FileChangeHandler(allowed_client_dn, callback)

    event = FileModifiedEvent(str(allowed_client_dn.parent / "other_file.txt"))
    handler.on_modified(event)

    callback.assert_not_called()
