/*
 * Copyright © 2023 Hochschule Heilbronn (ticket@hs-heilbronn.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.hhn.rz.services;

import de.hhn.rz.AbstractService;
import de.hhn.rz.db.entities.AuditAction;
import de.hhn.rz.dto.Account;
import de.hhn.rz.exception.GroupNotIdentifiableException;
import de.hhn.rz.exception.PermissionNotFoundException;
import de.hhn.rz.security.Role;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class KeycloakService extends AbstractService {

    private static final Pattern PATTERN_EMPLOYEE_ID = Pattern.compile("^[MmPp][0-9]*$");
    private final RealmResource client;
    private final CredentialService credentialService;
    private final AuditLogService auditLogService;

    public KeycloakService(@Autowired RealmResource client,
                           @Autowired CredentialService credentialService,
                           @Autowired AuditLogService auditLogService) {
        this.client = client;
        this.credentialService = credentialService;
        this.auditLogService = auditLogService;
    }

    public List<Account> findAccounts(Integer first, Integer max, String searchParameter) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        List<Account> allAccounts = List.of();
        //user did successfully authenticate with Keycloak, let's check for required helpdesk role.
        if (authentication != null) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

            if (authorities != null) {
                for (Role role : Role.values()) {
                    if (authorities.contains(role.asGrantedAuthority())) {
                        for (String groupAuth : role.groupAuthorizations()) {
                            List<Account> accounts = searchAccountsWithGroup(first, max, searchParameter, groupAuth);
                            allAccounts = Stream.concat(allAccounts.stream(), accounts.stream()).toList();
                        }
                    }
                }
            }
        }
        return allAccounts;
    }

    public void resetCredentials(String keycloakId, String seq) {
        checkParameter(keycloakId);
        checkParameter(seq);

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            Collection<? extends GrantedAuthority> ga = authentication.getAuthorities();
            if (ga != null) {
                final UserResource u = getUserResource(keycloakId, seq);
                Collection<String> userGroups = u.groups().stream().map(GroupRepresentation::getName).collect(Collectors.toList());
                for (Role r : Role.values()) {
                    if (ga.contains(r.asGrantedAuthority())) {
                        if (userGroups.stream().anyMatch(r.groupAuthorizations()::contains)) {
                            resetUserCredentials(seq, u);
                            return;
                        }
                    }
                }
            }
        }
        // other exception
        throw new PermissionNotFoundException();
    }

    private List<Account> searchAccountsWithGroup(Integer first, Integer max, String searchParameter, String group) {
        List<GroupRepresentation> groupRepresentations = client.groups().groups(group.toString(), true, 0, 2, false);

        if (groupRepresentations.size() != 1) {
            throw new GroupNotIdentifiableException();
        }

        String groupId = groupRepresentations.get(0).getId();
        List<UserRepresentation> groupMembers = client.groups().group(groupId).members();
        List<Account> groupAccounts = groupMembers.stream().map(Account::new).toList();

        List<Account> searchedAccounts;
        if (isEmployeeId(searchParameter)) {
            searchedAccounts = client.users().searchByAttributes("employeeID:" + searchParameter).stream().map(Account::new).toList();
        } else {
            searchedAccounts = client.users().search(searchParameter, first, max).stream().map(Account::new).toList();
        }
        return searchedAccounts.stream().filter(searchAcc -> groupAccounts.contains(searchAcc)).collect(Collectors.toList());
    }

    private UserResource getUserResource(String keycloakId, String seq) {
        UserResource u = client.users().get(keycloakId);
        if (u == null) {
            throw new IllegalArgumentException("No user found. ID='" + keycloakId + "' is invalid?!");
        }
        auditLogService.audit(AuditAction.RESET_CREDENTIALS, "user=" + u.toRepresentation().getUsername(), "keycloak-id=" + keycloakId, "seq=" + seq);
        return u;
    }

    private void resetUserCredentials(String seq, UserResource u) {
        // Remove 2FA and any other non password thingy
        for (CredentialRepresentation cr : u.credentials()) {
            if (!CredentialRepresentation.PASSWORD.equals(cr.getType())) {
                u.removeCredential(cr.getId());
            }
        }

        // Reset the password for the given user
        u.resetPassword(credentialService.getCredentials(seq));

    }


    private boolean isEmployeeId(String id) {
        if (id == null) {
            return false;
        }
        return PATTERN_EMPLOYEE_ID.matcher(id).find();
    }
}
