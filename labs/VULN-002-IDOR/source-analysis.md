# VULN-002 Source and Authorization Analysis

## Policy and data flow

Authenticated Alice and Bob may read articles in their synthetic run. Only an article's owner may modify it. Anonymous users cannot operate articles. Public knowledge of an ID is intentional and does not grant write permission.

PUT /api/labs/vuln002/articles/{id} -> IdorArticleController -> IdorService -> dedicated SqlSession -> IdorMapper -> MySQL lab_articles.

* Untrusted object reference: path id, validated as a positive long but not treated as authorization.
* Trusted identity: IdorPrincipal.id, produced only after database lookup and BCrypt verification by the chain-local authentication manager.
* Trusted experiment scope: IdorPrincipal.runId from lab_users, never a client field.
* Trusted owner: lab_articles.user_id loaded from the database.
* Payload: explicit title/content DTO, Bean Validation and unknown-field rejection; owner/id/role/runId cannot be assigned.
* Sink: parameterized UPDATE, explicitly committed in the dedicated MyBatis session.

The high-priority chain matches only /api/labs/vuln002/**. It stores its context and CSRF token under VULN002_SECURITY_CONTEXT and VULN002_CSRF; baseline context is separate. No CSRF or Session fixation protection is disabled. Experiment logout clears only experiment authentication/token state so an existing baseline login remains valid. Vulnerable application retains JSESSIONID; secure application uses VULN002SECSESSION in its experiment profile. Cookie scope is host/path, not TCP port; the shared-jar HTTP test proves both names are sent to both ports without identifying the wrong user.

## Vulnerable implementation

IdorService checks object existence and trusted run scope but omits the owner comparison. IdorMapper updates WHERE id=#{id} AND run_id=#{runId}. A logged-in Bob can select Alice's known ID within the same run and modify its title/content. Authentication, CSRF, validation and parameterized SQL all remain in effect. The persisted owner is not changed.

## Secure implementation

IdorService rejects original.userId()!=principal.getId() with 403. IdorMapper additionally constrains WHERE id=#{id} AND run_id=#{runId} AND user_id=#{currentUserId}. currentUserId comes only from principal.getId(). The application account has no permission to update user_id or run_id. Both variants use the same synthetic data shape, authentication conditions, validation and transaction behavior.

There are authorization differences in BOTH the Service and Mapper. They implement the same IDOR / Broken Access Control fix, rather than a single-line comparison. Mapper tests separately demonstrate its owner predicate, preventing a Service-only test from concealing an unconstrained update.

## Isolation and committed evidence

run_id is an extra teaching-lab isolation boundary in both variants, not the object ownership fix. Another run's object appears absent and cannot be modified, even in the vulnerable variant. Separate schemas prevent the vulnerable update from altering the secure comparison state.

IdorService uses sessions.openSession(false), commits successful updates, and rolls back on exceptional/uncommitted close. Original Spring transaction infrastructure is not assumed to manage this pool. Tests and HTTP tooling obtain NEW reader connections for id/owner/title/content/created_at/updated_at snapshots; request JSON is not database evidence. Safe refusal requires the entire original snapshot to remain equal; successful writes require committed expected values with stable id, owner and created_at. Untouched Bob/guardian articles must remain equal.

See README.md for reproduction and validation.md for executed checks, failure history and limits. No hidden-button or unguessable-ID substitute is used.
