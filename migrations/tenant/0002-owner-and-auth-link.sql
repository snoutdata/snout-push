-- Two things 0001 got wrong, found the first time push ran in a real project (2026-09-27).
--
-- 1. The project's owner could not read its own push data. The schema belongs to the sender's
--    role, which the owner may SET ROLE to but does not inherit, so `select * from push.deliveries`
--    in the owner's own SQL editor answered "permission denied for schema push". Whoever may
--    become the sender's role may now read and change what it keeps, EXCEPT the keys, which stay
--    readable by the sender alone (0001's rule for push.credentials). Nothing new is exposed: a
--    role that can SET ROLE to the sender could already read everything; this only stops it
--    having to.
--
-- 2. push.link_auth() read auth.users to delete orphaned devices before adding its foreign keys,
--    and the sender has no business reading the users table. It now needs only REFERENCES: the
--    key is added NOT VALID and then validated, and a validation that fails (a device of a user
--    deleted while push was not linked) leaves the key in force for every change from then on.
--
-- 3. The service role could write the migration ledger (see the end of this file).

-- Grants to every role that may SET ROLE to the one running this (the sender's), and is called by
-- the sender at every start, so a table added by a later migration is shared the same way.
CREATE FUNCTION push.share_with_members() RETURNS void
LANGUAGE plpgsql VOLATILE
SET search_path = ''
AS $$
DECLARE
	-- pg_auth_members.set_option is Postgres 16; before it, every member could SET ROLE.
	has_set_option boolean := EXISTS (
		SELECT FROM pg_catalog.pg_attribute
		WHERE attrelid = 'pg_catalog.pg_auth_members'::regclass AND attname = 'set_option'
	);
	member text;
BEGIN
	FOR member IN EXECUTE format(
		'SELECT DISTINCT m.member::regrole::text FROM pg_catalog.pg_auth_members m WHERE m.roleid = %L::regrole%s',
		current_user,
		CASE WHEN has_set_option THEN ' AND m.set_option' ELSE '' END
	)
	LOOP
		EXECUTE format('GRANT USAGE ON SCHEMA push TO %s', member);
		EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA push TO %s', member);
		EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA push TO %s', member);
		EXECUTE format('REVOKE ALL ON push.credentials FROM %s', member);
		-- The ledger is the runner's; a hand edit to it is how a migration runs twice.
		IF to_regclass('push.migrations') IS NOT NULL THEN
			EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON push.migrations FROM %s', member);
		END IF;
	END LOOP;
END
$$;

REVOKE ALL ON FUNCTION push.share_with_members() FROM PUBLIC;

SELECT push.share_with_members();

-- 0001 granted the service role ALL on every table in the schema, and the runner makes its ledger
-- before any file runs, so that included the ledger. Reading it is harmless; writing it is not.
DO $$
DECLARE
	service text := coalesce(nullif(current_setting('push.service_role', true), ''), 'service_role');
BEGIN
	IF to_regclass('push.migrations') IS NOT NULL THEN
		EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON push.migrations FROM %I', service);
	END IF;
END
$$;

-- Adds the foreign keys to auth.users once auth exists and the sender may point at it (REFERENCES,
-- granted when push is switched on). Idempotent; the sender calls it at start and hourly, since auth
-- may be switched on after push and its table made after the sender started.
CREATE OR REPLACE FUNCTION push.link_auth() RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
	users regclass;
BEGIN
	IF NOT EXISTS (SELECT FROM pg_namespace WHERE nspname = 'auth') OR NOT has_schema_privilege('auth', 'USAGE') THEN
		RETURN;
	END IF;
	users := to_regclass('auth.users');
	IF users IS NULL THEN
		RETURN;
	END IF;
	IF NOT has_table_privilege(users, 'REFERENCES') THEN
		RAISE EXCEPTION 'push may not reference auth.users (REFERENCES is granted when push is switched on)'
			USING ERRCODE = '42501';
	END IF;
	IF NOT EXISTS (SELECT FROM pg_constraint WHERE conname = 'devices_user_fk' AND conrelid = 'push.devices'::regclass) THEN
		ALTER TABLE push.devices ADD CONSTRAINT devices_user_fk
			FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
	END IF;
	IF NOT EXISTS (SELECT FROM pg_constraint WHERE conname = 'topic_members_user_fk' AND conrelid = 'push.topic_members'::regclass) THEN
		ALTER TABLE push.topic_members ADD CONSTRAINT topic_members_user_fk
			FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
	END IF;
	BEGIN
		ALTER TABLE push.devices VALIDATE CONSTRAINT devices_user_fk;
		ALTER TABLE push.topic_members VALIDATE CONSTRAINT topic_members_user_fk;
	EXCEPTION WHEN foreign_key_violation THEN
		RAISE WARNING 'push has rows for users auth.users no longer holds; the link holds for every change from now on';
	END;
END
$$;
