"""
SSSD Authentication Test Cases

:requirement: access control access_filter
"""

from __future__ import annotations

import pytest
import pudb
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__single_ldap_attribute_permits_user_login(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: LDAP attribute permits user login
    :setup:
        1. Create users ‘user1’ and ‘user2’
        2. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = uid|samAccountName = user1’
        3. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
    :expectedresults:
        1. User1 is successfully logged in
        2. User2 is not logged in
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")

    # Logic to determine the access provider and filter based on the provider
    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "samAccountName=user1"
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "uid=user1"

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User login!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User cannot login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__group_attributes_permits_user_login(client: Client, provider: GenericProvider, method: str):
    """
    :title: LDAP attribute permits user login
    :description:   LDAP has options to be tested as rfc23007bis and rfc2307.
                    The former uses memberOf and the latter member. AD uses memberof, so LDAP will cover member.
    :setup:
        1. Create users ‘user1’, ‘user2’ and group ‘group1’ adding ‘user1’ as a member
        2. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = GROUP ATTRIBUTE’
        3. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
    :expectedresults:
        1. User1 is successfully logged in
        2. User2 is not logged in
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")

    group1 = provider.group("group1").add()

    group1.add_member(user1)

    # ldapsearch -x -LLL -H ldap://master.ldap.test -D "cn=root,dc=master,dc=ldap,dc=test" -w Secret123 -b "dc=master,dc=ldap,dc=test" "(&(cn=group1))"

    # Logic to determine the access provider and filter based on the provider
    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "(&(memberof=cn=group1))"
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(&(CN=group1))"

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User login!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User cannot login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__ldap_query_with_wildcard_permits_user_login(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: LDAP query with wildcard permits user login
    :description: LDAP query with wildcard permits user login
    :setup:
        1. Create users ‘user1’ with a valid mail attribute, ‘user2’ with a missing mail attribute
        2. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = *@domain.com’
        3. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
    :expectedresults:
        1. User1 is successfully logged in
        2. User2 is not logged in
    :customerscenario: False
    """
    # pudb.set_trace()

    user1 = provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")

    group1 = provider.group("group1").add()

    group1.add_member(user1)

    # Logic to determine the access provider and filter based on the provider
    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "(&(memberof=cn=group1))"
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(&(memberof=cn=group1))"

    pudb.set_trace()

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User login!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User cannot login!"


"""
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_access_filter__ldap_query_with_wildcard_permits_user_login(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """ """
    :title: LDAP query with wildcard permits user login
    :description: LDAP query with wildcard permits user login
    :setup:
        1. Create users ‘user1’ with a valid mail attribute, ‘user2’ with a missing mail attribute
        2. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = *@domain.com’
        3. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
    :expectedresults:
        1. User1 is successfully logged in
        2. User2 is not logged in
    :customerscenario: False
    """

"""
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
@pytest.mark.parametrize("filter", [" = ", " = "])
def test_access_filter__ldap_query_with_and_or_not_permits_user_login(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """ """
    :title: LDAP query with AND | OR | NOT attributes permits user login
    :description: LDAP attribute permits user login
    :setup:
        1. Create user ‘user1’ and ‘username’ as Joe and email as user1@domain.com
        2. Create user ‘user2’ and ‘username’ as Daniela and email as user2@domain.com
        3. Create user ‘user3’ and ‘username’ as Jack and email as user3@example.com
        4. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = *@domain.com’
        5. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
    :expectedresults:
        1. User1 is successfully logged in
        2. User2 is not logged in
    :customerscenario: False
    """

"""
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
@pytest.mark.parametrize("filter", ["INVALID_ATTR = value", "ATTR = "])
def test_access_filter__invalid_ldap_query_denies_user_login(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """ """
    :title: Invalid access filter queries denies user logins
    :setup:
        1. Create users ‘user1’, ‘user2’
        2. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = | *access_filter = INVALID_ATTRIBUTE’
        3. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
    :expectedresults:
        1. User1 is successfully logged in
        2. User2 is not logged in
    :customerscenario: False
    """

"""
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_access_filter__ldap_attributes_approximately_greater_and_less_than_permits_user_login(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """ """
    :title: LDAP attribute permits user login
    :description: LDAP attribute permits user login
    :setup:
        1. Create users ‘user1’, ‘user2’ and group ‘group1’ adding ‘user1’ as a member
        2. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = GROUP ATTRIBUTE’
        3. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
    :expectedresults:
        1. User1 is successfully logged in
        2. User2 is not logged in
    :customerscenario: False
    """
