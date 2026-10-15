-- push.link_auth() in either layout of a project's database (the new layout keeps its people in
-- snout_identity.people, the old one in auth.users; a database has one or the other). The same
-- function as 0002's in everything else: it returns when there is no such schema or table, or the
-- sender may not use the schema; it refuses without REFERENCES; it adds each key NOT VALID and then
-- validates, and a validation that fails leaves the key in force for every change from then on.

CREATE OR REPLACE FUNCTION push.link_auth() RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
	-- The schema and table that hold the project's people, as this database names them.
	schema_name text := CASE WHEN to_regnamespace('snout_identity') IS NOT NULL THEN 'snout_identity' ELSE 'auth' END;
	target text := CASE WHEN schema_name = 'snout_identity' THEN 'snout_identity.people' ELSE 'auth.users' END;
	users regclass;
BEGIN
	IF NOT EXISTS (SELECT FROM pg_namespace WHERE nspname = schema_name) OR NOT has_schema_privilege(schema_name, 'USAGE') THEN
		RETURN;
	END IF;
	users := to_regclass(target);
	IF users IS NULL THEN
		RETURN;
	END IF;
	IF NOT has_table_privilege(users, 'REFERENCES') THEN
		RAISE EXCEPTION 'push may not reference % (REFERENCES is granted when push is switched on)', target
			USING ERRCODE = '42501';
	END IF;
	IF NOT EXISTS (SELECT FROM pg_constraint WHERE conname = 'devices_user_fk' AND conrelid = 'push.devices'::regclass) THEN
		EXECUTE format('ALTER TABLE push.devices ADD CONSTRAINT devices_user_fk '
			'FOREIGN KEY (user_id) REFERENCES %s (id) ON DELETE CASCADE NOT VALID', target);
	END IF;
	IF NOT EXISTS (SELECT FROM pg_constraint WHERE conname = 'topic_members_user_fk' AND conrelid = 'push.topic_members'::regclass) THEN
		EXECUTE format('ALTER TABLE push.topic_members ADD CONSTRAINT topic_members_user_fk '
			'FOREIGN KEY (user_id) REFERENCES %s (id) ON DELETE CASCADE NOT VALID', target);
	END IF;
	BEGIN
		ALTER TABLE push.devices VALIDATE CONSTRAINT devices_user_fk;
		ALTER TABLE push.topic_members VALIDATE CONSTRAINT topic_members_user_fk;
	EXCEPTION WHEN foreign_key_violation THEN
		RAISE WARNING 'push has rows for users % no longer holds; the link holds for every change from now on', target;
	END;
END
$$;
