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
package de.hhn.rz.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public enum Role {

    HHN_HELPDESK_ADMIN("HHN_HELPDESK_ADMIN", List.of()),
    HHN_HELPDESK_IT("HHN_HELPDESK_IT", List.of("FAKULTAET_IT")),
    HHN_HELPDESK_IB("HHN_HELPDESK_IB", List.of("FAKULTAET_IB")),
    HHN_HELPDESK_VW("HHN_HELPDESK_VW", List.of("FAKULTAET_VW")),
    HHN_HELPDESK_RZ("HHN_HELPDESK_RZ", List.of("FAKULTAET_IT", "FAKULTAET_IB", "FAKULTAET_VW"));

    private final String role;
    private final List<String> authorities;

    Role(String role, List<String> groupAuthorizations) {
        this.role = role;
        this.authorities = groupAuthorizations;
    }

    public GrantedAuthority asGrantedAuthority() {
        return new SimpleGrantedAuthority(withPrefix());
    }

    public List<String> groupAuthorizations() {
        return authorities;
    }

    public String withPrefix() {
        return "ROLE_" + this.toString();
    }
    public String toString() {
        return role;
    }
}
