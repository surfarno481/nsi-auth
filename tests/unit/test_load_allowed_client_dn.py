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

from flask import Flask
from flask.testing import FlaskClient


def test_load_dn_from_file(client: FlaskClient, allowed_client_dn: Path) -> None:
    """Verify that DNs are loaded from the configured file."""
    from nsi_auth import state

    assert len(state.allowed_client_subject_dn) == 2
    assert "CN=CertA,OU=Dept X,O=Company Y,C=Z" in state.allowed_client_subject_dn
    assert "CN=CertB,OU=Dept X,O=Company Y,C=Z" in state.allowed_client_subject_dn


def test_load_dn_ignores_blank_lines(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that blank lines in the DN file are ignored."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("\n\nCN=CertA,OU=Dept X,O=Company Y,C=Z\n\n\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    assert state.allowed_client_subject_dn == ["CN=CertA,OU=Dept X,O=Company Y,C=Z"]


def test_load_dn_ignores_whitespace_only_lines(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that whitespace-only lines in the DN file are ignored."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("  \n\t\nCN=CertA,OU=Dept X,O=Company Y,C=Z\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    assert state.allowed_client_subject_dn == ["CN=CertA,OU=Dept X,O=Company Y,C=Z"]


def test_load_dn_strips_whitespace(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that leading/trailing whitespace is stripped from DNs."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("  CN=CertA,OU=Dept X,O=Company Y,C=Z  \n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    assert state.allowed_client_subject_dn == ["CN=CertA,OU=Dept X,O=Company Y,C=Z"]


def test_load_dn_empty_file(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that an empty file results in an empty DN list."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    assert state.allowed_client_subject_dn == []


def test_load_dn_nonexistent_file_keeps_previous_state(application: Flask, tmp_path: Path) -> None:
    """Verify that loading from a nonexistent file preserves the previous state."""
    from nsi_auth import load_allowed_client_dn, state

    state.allowed_client_subject_dn = ["CN=Existing"]
    load_allowed_client_dn(tmp_path / "nonexistent.txt")

    assert state.allowed_client_subject_dn == ["CN=Existing"]


def test_load_dn_no_update_when_unchanged(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that loading the same file content does not reassign state."""
    from nsi_auth import load_allowed_client_dn, state

    load_allowed_client_dn(allowed_client_dn)
    original_list = state.allowed_client_subject_dn

    load_allowed_client_dn(allowed_client_dn)
    assert state.allowed_client_subject_dn is original_list


def test_load_dn_updates_on_file_change(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that changing the file content updates the state."""
    from nsi_auth import load_allowed_client_dn, state

    load_allowed_client_dn(allowed_client_dn)
    assert len(state.allowed_client_subject_dn) == 2

    allowed_client_dn.write_text("CN=NewCert,O=NewOrg,C=NL\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    assert state.allowed_client_subject_dn == ["CN=NewCert,O=NewOrg,C=NL"]


def test_validate_after_dn_reload(client: FlaskClient, allowed_client_dn: Path) -> None:
    """Verify that after reloading the DN file, validation uses the new list."""
    from nsi_auth import load_allowed_client_dn

    load_allowed_client_dn(allowed_client_dn)
    response = client.get("/validate", headers={"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=Z"})
    assert response.status_code == 200

    allowed_client_dn.write_text("CN=NewCert,O=NewOrg,C=NL\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    response = client.get("/validate", headers={"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=Z"})
    assert response.status_code == 403

    response = client.get("/validate", headers={"ssl-client-subject-dn": "CN=NewCert,O=NewOrg,C=NL"})
    assert response.status_code == 200
