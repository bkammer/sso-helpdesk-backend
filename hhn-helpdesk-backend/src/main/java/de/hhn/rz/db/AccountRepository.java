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
package de.hhn.rz.db;

import de.hhn.rz.db.entities.AccountCredential;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountRepository extends CrudRepository<AccountCredential, Long> {

    @Query("SELECT a FROM AccountCredential a WHERE a.seq = (?1)")
    AccountCredential getBySeq(String seq);

    @Query(nativeQuery = true, value = "SELECT EXISTS (SELECT a FROM account_credential  a WHERE a.seq = (?1))")
    boolean existsBySeq(String seq);

    @Query(nativeQuery = true, value = "SELECT nextval('master_sequence');")
    int getNextSeq();

}
