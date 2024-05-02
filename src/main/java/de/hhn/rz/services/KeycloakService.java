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
import jakarta.ws.rs.ForbiddenException;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class KeycloakService extends AbstractService {

    private final static Logger logger = Logger.getLogger(KeycloakService.class.getName());
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
        // TODO: Add audit log
        Collection<String> roles = Set.of();
        final Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof OidcUser ou) {
            if (ou.hasClaim("realm_access")) {
                roles = (Collection<String>) ou.getClaimAsMap("realm_access").get("roles");
            }

        } //else {
//            return new UserInfo("N/A", Collections.emptySet());
//        }

        // Roles
        List<UserRepresentation> allGroupMembers = List.of();
        for (String role : roles) {
            // TODO: Check max parameter if it could be reduced from 1000 to maybe 1
            List<GroupRepresentation> groups = client.groups().groups(role.toString(), true, 0, 1000, false);
//            logger.info("groups: " + groups);

            if (groups.size() > 0) {
                List list = groups.stream().map(GroupRepresentation::getId).collect(Collectors.toList());
                // TODO: Bessere Implementierung > kein collect mit Collectors.toList()?
                String groupId = list.get(0).toString();
                List<UserRepresentation> groupMembers = client.groups().group(groupId).members();
                allGroupMembers = Stream.concat(allGroupMembers.stream(), groupMembers.stream()).toList();
            }
        }

        List<Account> groupAccounts = allGroupMembers.stream().map(Account::new).toList();

        // Get all users that mach a given string
        List<Account> searchedAccounts;
        if (isEmployeeId(searchParameter)) {
            searchedAccounts = client.users().searchByAttributes("employeeID:" + searchParameter).stream().map(Account::new).toList();
        } else {
            searchedAccounts = client.users().search(searchParameter, first, max).stream().map(Account::new).toList();
        }

        // Filter accounts
        return searchedAccounts.stream().filter(searchAcc -> groupAccounts.contains(searchAcc)).collect(Collectors.toList());

//        if (isEmployeeId(searchParameter)) {
//            return client.users().searchByAttributes("employeeID:" + searchParameter).stream().map(Account::new).toList();
//        }
//        return client.users().search(searchParameter, first, max).stream().map(Account::new).toList();
    }

    public void resetCredentials(String keycloakId, String seq) {
        logger.info("resetCredentials called");
        // TODO: Implement access control for resetCredentials
        checkParameter(keycloakId);
        checkParameter(seq);

        final UserResource u = client.users().get(keycloakId);
        if (u == null) {
            throw new IllegalArgumentException("No user found. ID='" + keycloakId + "' is invalid?!");
        }
        auditLogService.audit(AuditAction.RESET_CREDENTIALS, "user=" + u.toRepresentation().getUsername(), "keycloak-id=" + keycloakId, "seq=" + seq);

        // Get group of HS-user
        Collection<String> userGroups = u.groups().stream().map(GroupRepresentation::getName).collect(Collectors.toList());

        Collection<String> roles = Set.of();
        final Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof OidcUser ou) {
            if (ou.hasClaim("realm_access")) {
                roles = (Collection<String>) ou.getClaimAsMap("realm_access").get("roles");
            }
        }

        logger.info("userGroups: " + userGroups);
        logger.info("roles: " + roles);
        // TODO: Work with granted authorities instead of string matching.
        // It is possible to get the authorities from the HD-User
        // Check how make a granted authority for the UserGroup.

        // Check if user has the permission to reset credentials
        if (!Collections.disjoint(userGroups, roles)) {

            // Remove 2FA and any other non password thingy
            for (CredentialRepresentation cr : u.credentials()) {
                if (!CredentialRepresentation.PASSWORD.equals(cr.getType())) {
                    u.removeCredential(cr.getId());
                }
            }

            // Reset the password for the given user
            u.resetPassword(credentialService.getCredentials(seq));
        } else {
            throw new ForbiddenException();
        }
    }


    private boolean isEmployeeId(String id) {
        if (id == null) {
            return false;
        }
        return PATTERN_EMPLOYEE_ID.matcher(id).find();
    }
}
