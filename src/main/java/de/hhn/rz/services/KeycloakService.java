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
import de.hhn.rz.security.Role;
import jakarta.ws.rs.ForbiddenException;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.*;
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
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        List<Account> allAccounts = List.of();
        //user did successfully authenticate with Keycloak, let's check for required helpdesk role.
        if (authentication != null) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            if (authorities != null) {
                final GrantedAuthority gaIt = Role.HHN_HELPDESK_IT.asGrantedAuthority();
                final GrantedAuthority gaIb = Role.HHN_HELPDESK_IB.asGrantedAuthority();
                final GrantedAuthority gaVW = Role.HHN_HELPDESK_VW.asGrantedAuthority();
                if (authorities.contains(gaIt)) {
                    //logger.info("Authority IT");
                    allAccounts = Stream.concat(allAccounts.stream(), findAccountsSearchWithGroup(first, max, searchParameter, "FAKULTAET_IT").stream()).toList();
                    //logger.info(allAccounts.toString());
                }
                if (authorities.contains(gaIb)) {
                    //logger.info("Authority IB");
                    allAccounts = Stream.concat(allAccounts.stream(), findAccountsSearchWithGroup(first, max, searchParameter, "FAKULTAET_IB").stream()).toList();
                    //logger.info(allAccounts.toString());
                }
                if (authorities.contains(gaVW)) {
                    //logger.info("Authority VW");
                    allAccounts = Stream.concat(allAccounts.stream(), findAccountsSearchWithGroup(first, max, searchParameter, "FAKULTAET_VW").stream()).toList();
                    //logger.info(allAccounts.toString());
                }

                // Error if no GrantedAuthority matches
            }
        }

        return allAccounts;




//        if (isEmployeeId(searchParameter)) {
//            return client.users().searchByAttributes("employeeID:" + searchParameter).stream().map(Account::new).toList();
//        }
//        return client.users().search(searchParameter, first, max).stream().map(Account::new).toList();
    }

    public void resetCredentials(String keycloakId, String seq) {
        //logger.info("resetCredentials called");
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

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        List<Account> allAccounts = List.of();
        //user did successfully authenticate with Keycloak, let's check for required helpdesk role.
        if (authentication != null) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            if (authorities != null) {
                // create granted authorities
                final GrantedAuthority gaIt = Role.HHN_HELPDESK_IT.asGrantedAuthority();
                final GrantedAuthority gaIb = Role.HHN_HELPDESK_IB.asGrantedAuthority();
                final GrantedAuthority gaVW = Role.HHN_HELPDESK_VW.asGrantedAuthority();
                // check which authority the user has

                // Berechtigungscheck bevor der credentialservice aufgerufen wird.
                
                if (authorities.contains(gaIt)) {
                    logger.info("Authority IT");
                    // reset credentials
                    if (userGroups.contains("FAKULTAET_IT")){
                        logger.info("User Group IT");
                        // Remove 2FA and any other non password thingy
                        for (CredentialRepresentation cr : u.credentials()) {
                            if (!CredentialRepresentation.PASSWORD.equals(cr.getType())) {
                                u.removeCredential(cr.getId());
                            }
                        }

                        // Reset the password for the given user
                        u.resetPassword(credentialService.getCredentials(seq));
                        return;
                    }
                }
                if (authorities.contains(gaIb)) {
                    logger.info("Authority IB");
                    // reset credentials
                    if (userGroups.contains("FAKULTAET_IB")){
                        logger.info("User Group IT");
                        // Remove 2FA and any other non password thingy
                        for (CredentialRepresentation cr : u.credentials()) {
                            if (!CredentialRepresentation.PASSWORD.equals(cr.getType())) {
                                u.removeCredential(cr.getId());
                            }
                        }

                        // Reset the password for the given user
                        u.resetPassword(credentialService.getCredentials(seq));
                        return;
                    }
                }
                if (authorities.contains(gaVW)) {
                    logger.info("Authority VW");
                    // reset credentials
                    if (userGroups.contains("FAKULTAET_VW")){
                        logger.info("User Group IT");
                        // Remove 2FA and any other non password thingy
                        for (CredentialRepresentation cr : u.credentials()) {
                            if (!CredentialRepresentation.PASSWORD.equals(cr.getType())) {
                                u.removeCredential(cr.getId());
                            }
                        }

                        // Reset the password for the given user
                        u.resetPassword(credentialService.getCredentials(seq));
                        return;
                    }
                }
                // Throw other exception
                throw new IllegalArgumentException("No user found. ID='" + keycloakId + "' is invalid?!");
                // Error if no GrantedAuthority matches
            }
        }
    }


    private boolean isEmployeeId(String id) {
        if (id == null) {
            return false;
        }
        return PATTERN_EMPLOYEE_ID.matcher(id).find();
    }

    private List<Account> findAccountsSearchWithGroup (Integer first, Integer max, String searchParameter, String group) {

        List<UserRepresentation> groupMembers = List.of();
        // Check max parameter if it could be reduced from 1000 to maybe 1
        List<GroupRepresentation> groupRepresentations = client.groups().groups(group.toString(), true, 0, 1000, false);
        //logger.info("Group: " + groupRepresentations);

        if (groupRepresentations.size() == 1) {
            List list = groupRepresentations.stream().map(GroupRepresentation::getId).collect(Collectors.toList());
            // Bessere Implementierung > kein collect mit Collectors.toList()?
            String groupId = list.get(0).toString();
            groupMembers = client.groups().group(groupId).members();
        } else {
            // throw Exception?
        }

        //logger.info("Group members: " + groupMembers);

        List<Account> groupAccounts = groupMembers.stream().map(Account::new).toList();

        //logger.info("Group accounts: " + groupAccounts);

        // Get all users that mach a given string
        List<Account> searchedAccounts;
        if (isEmployeeId(searchParameter)) {
            searchedAccounts = client.users().searchByAttributes("employeeID:" + searchParameter).stream().map(Account::new).toList();
        } else {
            searchedAccounts = client.users().search(searchParameter, first, max).stream().map(Account::new).toList();
        }

        //logger.info("Searched accounts: " + searchedAccounts);

        List<Account> resultAccount = searchedAccounts.stream().filter(searchAcc -> groupAccounts.contains(searchAcc)).collect(Collectors.toList());
        //logger.info("ResultAccounts: " + resultAccount);
        return resultAccount;
    }
}
