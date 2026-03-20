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

import rfc4514_cmp


def test_load_dn_from_file(client: FlaskClient, allowed_client_dn: Path) -> None:
    """Verify that DNs are loaded from the configured file."""
    from nsi_auth import state
    
    a_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=CertA,OU=Dept X,O=Company Y,C=ZZ")
    b_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=CertB,OU=Dept X,O=Company Y,C=ZZ")

    assert len(state.allowed_client_subject_dn_names) == 2
    assert a_name in state.allowed_client_subject_dn_names
    assert b_name in state.allowed_client_subject_dn_names


def test_load_dn_ignores_blank_lines(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that blank lines in the DN file are ignored."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("\n\nCN=CertA,OU=Dept X,O=Company Y,C=ZZ\n\n\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    a_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=CertA,OU=Dept X,O=Company Y,C=ZZ")
    assert state.allowed_client_subject_dn_names == [a_name]


def test_load_dn_ignores_whitespace_only_lines(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that whitespace-only lines in the DN file are ignored."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("  \n\t\nCN=CertA,OU=Dept X,O=Company Y,C=ZZ\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    a_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=CertA,OU=Dept X,O=Company Y,C=ZZ")
    assert state.allowed_client_subject_dn_names == [a_name]


def test_load_dn_strips_whitespace(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that leading/trailing whitespace is stripped from DNs."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("  CN=CertA,OU=Dept X,O=Company Y,C=ZZ  \n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    a_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=CertA,OU=Dept X,O=Company Y,C=ZZ")
    assert state.allowed_client_subject_dn_names == [a_name]


def test_load_dn_empty_file(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that an empty file results in an empty DN list."""
    from nsi_auth import load_allowed_client_dn, state

    allowed_client_dn.write_text("", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    assert state.allowed_client_subject_dn_names == []


def test_load_dn_nonexistent_file_keeps_previous_state(application: Flask, tmp_path: Path) -> None:
    """Verify that loading from a nonexistent file preserves the previous state."""
    from nsi_auth import load_allowed_client_dn, state

    e_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=Existing")

    state.allowed_client_subject_dn_names = [e_name]
    load_allowed_client_dn(tmp_path / "nonexistent.txt")

    assert state.allowed_client_subject_dn_names == [e_name]



def test_load_dn_no_update_when_unchanged(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that loading the same file content does not reassign state."""
    from nsi_auth import load_allowed_client_dn, state

    load_allowed_client_dn(allowed_client_dn)
    original_list = state.allowed_client_subject_dn_names

    load_allowed_client_dn(allowed_client_dn)
    assert state.allowed_client_subject_dn_names is original_list


def test_load_dn_updates_on_file_change(application: Flask, allowed_client_dn: Path) -> None:
    """Verify that changing the file content updates the state."""
    from nsi_auth import load_allowed_client_dn, state

    load_allowed_client_dn(allowed_client_dn)
    assert len(state.allowed_client_subject_dn_names) == 2

    allowed_client_dn.write_text("CN=NewCert,O=NewOrg,C=NL\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    n_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=NewCert,O=NewOrg,C=NL")
    assert state.allowed_client_subject_dn_names == [n_name]


def test_validate_after_dn_reload(client: FlaskClient, allowed_client_dn: Path) -> None:
    """Verify that after reloading the DN file, validation uses the new list."""
    from nsi_auth import load_allowed_client_dn

    load_allowed_client_dn(allowed_client_dn)
    response = client.get("/validate", headers={"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZ"})
    assert response.status_code == 200

    allowed_client_dn.write_text("CN=NewCert,O=NewOrg,C=NL\n", encoding="utf-8")
    load_allowed_client_dn(allowed_client_dn)

    response = client.get("/validate", headers={"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZ"})
    assert response.status_code == 403

    response = client.get("/validate", headers={"ssl-client-subject-dn": "CN=NewCert,O=NewOrg,C=NL"})
    assert response.status_code == 200
