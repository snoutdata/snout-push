-- The push schema's rules, driven as each role would drive them. Run by tests/schema.sh against a
-- fresh Postgres with the migration applied; any failed ASSERT stops it (ON_ERROR_STOP).

\set ON_ERROR_STOP on
\set QUIET on

\set alice '00000000-0000-4000-8000-00000000000a'
\set bob '00000000-0000-4000-8000-00000000000b'
\set token 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90'

-- Alice registers her phone.
SET ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"' || :'alice' || '","role":"authenticated"}', false);
SELECT push.register_device('apns', :'token', apns_environment => 'production', app => 'com.example.app') AS alice_device \gset
DO $$ BEGIN
	ASSERT (SELECT count(*) FROM push.devices) = 1, 'alice sees her device';
	ASSERT push.uid() = '00000000-0000-4000-8000-00000000000a', 'push.uid() reads the claims';
END $$;

-- Registering again is the same row, refreshed, not a second one.
SELECT push.register_device('apns', :'token', apns_environment => 'production') AS again \gset
DO $$ BEGIN ASSERT (SELECT count(*) FROM push.devices) = 1, 're-registering does not duplicate'; END $$;
SELECT :'again' = :'alice_device' AS same_row \gset
\if :same_row
\else
	\echo 'FAIL: re-registering made a new row'
	SELECT 1/0;
\endif

-- Bob cannot see it.
SELECT set_config('request.jwt.claims', '{"sub":"' || :'bob' || '","role":"authenticated"}', false);
DO $$ BEGIN ASSERT (SELECT count(*) FROM push.devices) = 0, 'bob cannot see alice''s device'; END $$;

-- A2: the phone passes to Bob, so it stops notifying Alice.
SELECT push.register_device('apns', :'token', apns_environment => 'production') AS bob_device \gset
RESET ROLE;
DO $$ BEGIN
	ASSERT (SELECT count(*) FROM push.devices) = 1, 'the token moved: one row';
	ASSERT (SELECT user_id FROM push.devices) = '00000000-0000-4000-8000-00000000000b', 'and it is bob''s';
END $$;

-- With shared_devices, both keep it (account switching).
UPDATE push.settings SET shared_devices = true;
SET ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"' || :'alice' || '","role":"authenticated"}', false);
SELECT push.register_device('apns', :'token', apns_environment => 'production') AS alice_device \gset
RESET ROLE;
DO $$ BEGIN ASSERT (SELECT count(*) FROM push.devices) = 2, 'shared: two rows'; END $$;
UPDATE push.settings SET shared_devices = false;

-- Anonymous devices are refused until the project allows them.
SET ROLE anon;
SELECT set_config('request.jwt.claims', '{"role":"anon"}', false);
DO $$ BEGIN
	PERFORM push.register_device('web', 'https://fcm.googleapis.com/fcm/send/x', web_p256dh => 'k', web_auth => 'a');
	RAISE EXCEPTION 'FAIL: an anonymous device was accepted';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
RESET ROLE;
UPDATE push.settings SET anonymous_devices = true;
SET ROLE anon;
SELECT push.register_device('web', 'https://fcm.googleapis.com/fcm/send/x', web_p256dh => 'k', web_auth => 'a') AS anon_device \gset
RESET ROLE;
DO $$ BEGIN ASSERT (SELECT count(*) FROM push.devices WHERE user_id IS NULL) = 1, 'anonymous web device stored'; END $$;

-- The shape checks: a web device needs its keys, an apns one its environment.
DO $$ BEGIN
	INSERT INTO push.devices (user_id, transport, token) VALUES (gen_random_uuid(), 'web', 'https://x');
	RAISE EXCEPTION 'FAIL: a web device without keys';
EXCEPTION WHEN check_violation THEN NULL;
END $$;
DO $$ BEGIN
	INSERT INTO push.devices (user_id, transport, token) VALUES (gen_random_uuid(), 'apns', 'ab');
	RAISE EXCEPTION 'FAIL: an apns device without an environment';
EXCEPTION WHEN check_violation THEN NULL;
END $$;

-- P8: a signed-in user may NOT send until the customer writes a policy.
SET ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"' || :'alice' || '","role":"authenticated"}', false);
DO $$ BEGIN
	PERFORM push.send('{"title":"hi"}', user_ids => ARRAY['00000000-0000-4000-8000-00000000000b'::uuid]);
	RAISE EXCEPTION 'FAIL: a user sent with no policy';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
RESET ROLE;

-- The customer allows a user to notify themselves only.
CREATE POLICY send_to_self ON push.messages FOR INSERT TO authenticated
	WITH CHECK (target_user_ids = ARRAY[push.uid()]);
SET ROLE authenticated;
SELECT push.send('{"title":"note to self"}', user_ids => ARRAY[:'alice'::uuid]) AS own_message \gset
DO $$ BEGIN
	PERFORM push.send('{"title":"hi bob"}', user_ids => ARRAY['00000000-0000-4000-8000-00000000000b'::uuid]);
	RAISE EXCEPTION 'FAIL: the policy let alice notify bob';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
-- created_by is the caller whatever the insert says, and a new row is always queued.
INSERT INTO push.messages (notification, target_user_ids, created_by, status)
	VALUES ('{"title":"forged"}', ARRAY[:'alice'::uuid], :'bob', 'sent');
DO $$ BEGIN
	ASSERT (SELECT count(*) FROM push.messages WHERE created_by = '00000000-0000-4000-8000-00000000000b') = 0,
		'created_by cannot be forged';
	ASSERT (SELECT count(*) FROM push.messages WHERE status <> 'queued') = 0, 'a new message is queued';
END $$;

-- A sender cancels their own queued message, and can do nothing else to it.
UPDATE push.messages SET status = 'cancelled' WHERE id = :own_message;
DO $$ BEGIN
	ASSERT (SELECT status FROM push.messages WHERE id = (SELECT min(id) FROM push.messages)) = 'cancelled', 'cancelled';
END $$;
DO $$ BEGIN
	UPDATE push.messages SET status = 'sent' WHERE status = 'queued';
	RAISE EXCEPTION 'FAIL: a user marked their message sent';
EXCEPTION WHEN insufficient_privilege OR check_violation THEN NULL;
END $$;
RESET ROLE;

-- Exactly one target.
SET ROLE service_role;
DO $$ BEGIN
	PERFORM push.send('{"title":"x"}', user_ids => ARRAY[gen_random_uuid()], topic => 'news');
	RAISE EXCEPTION 'FAIL: two targets';
EXCEPTION WHEN check_violation THEN NULL;
END $$;
DO $$ BEGIN
	PERFORM push.send('{"title":"x"}');
	RAISE EXCEPTION 'FAIL: no target';
EXCEPTION WHEN check_violation THEN NULL;
END $$;
-- The service role sends to anyone (it has no sub, so it keeps what it writes).
SELECT push.send('{"title":"from the server"}', user_ids => ARRAY[:'bob'::uuid]) AS server_message \gset
RESET ROLE;

-- P11: receipts only for the caller's own device.
INSERT INTO push.deliveries (message_id, device_id, transport, status)
	VALUES (:server_message, :'bob_device', 'apns', 'accepted');
SET ROLE authenticated;
SELECT push.report_receipt((SELECT max(id) FROM push.deliveries), 'opened') AS alice_receipt \gset
SELECT set_config('request.jwt.claims', '{"sub":"' || :'bob' || '","role":"authenticated"}', false);
DO $$ BEGIN ASSERT (SELECT count(*) FROM push.deliveries) = 1, 'bob sees the delivery to his device'; END $$;
SELECT push.report_receipt((SELECT max(id) FROM push.deliveries), 'opened') AS bob_receipt \gset
RESET ROLE;
DO $$ BEGIN
	ASSERT (SELECT received_at IS NOT NULL AND opened_at IS NOT NULL FROM push.deliveries), 'opened implies received';
END $$;
SELECT (:'alice_receipt' = 'f' AND :'bob_receipt' = 't') AS receipts_ok \gset
\if :receipts_ok
\else
	\echo 'FAIL: receipts: alice' :alice_receipt 'bob' :bob_receipt
	SELECT 1/0;
\endif

-- Topics: users join and leave for themselves only.
INSERT INTO push.topics (name) VALUES ('news');
SET ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"' || :'alice' || '","role":"authenticated"}', false);
INSERT INTO push.topic_members (topic, user_id) VALUES ('news', :'alice');
DO $$ BEGIN
	INSERT INTO push.topic_members (topic, user_id) VALUES ('news', '00000000-0000-4000-8000-00000000000b');
	RAISE EXCEPTION 'FAIL: alice subscribed bob';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
RESET ROLE;
DO $$ BEGIN
	INSERT INTO push.topics (name) VALUES ('bad name!');
	RAISE EXCEPTION 'FAIL: a topic name with a space';
EXCEPTION WHEN check_violation THEN NULL;
END $$;

-- link_auth: once auth exists, a deleted user takes their devices and memberships.
CREATE SCHEMA auth;
CREATE TABLE auth.users (id uuid PRIMARY KEY);
INSERT INTO auth.users VALUES (:'alice'), (:'bob');
SELECT push.link_auth();
SELECT push.link_auth();
DELETE FROM auth.users WHERE id = :'bob';
DO $$ BEGIN
	ASSERT (SELECT count(*) FROM push.devices WHERE user_id = '00000000-0000-4000-8000-00000000000b') = 0,
		'bob''s devices went with him';
	ASSERT (SELECT count(*) FROM push.deliveries WHERE device_id IS NULL) = 1, 'the log row stays';
	ASSERT (SELECT count(*) FROM push.topic_members) = 1, 'alice is still subscribed';
END $$;

-- The keys: nobody but the sender's role reads them, the service role included.
INSERT INTO push.credentials (kind, value, summary) VALUES ('vapid', '{"keys": {}, "current": "v1"}', '{"current": "v1"}');
SET ROLE service_role;
DO $$ BEGIN
	PERFORM value FROM push.credentials;
	RAISE EXCEPTION 'FAIL: the service role read the push keys';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
DO $$ BEGIN ASSERT (SELECT count(*) FROM push.credential_summaries()) = 1, 'the summaries are readable'; END $$;
SET ROLE authenticated;
DO $$ BEGIN
	PERFORM value FROM push.credentials;
	RAISE EXCEPTION 'FAIL: a user read the push keys';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
DO $$ BEGIN
	PERFORM push.credential_summaries();
	RAISE EXCEPTION 'FAIL: a user read the key summaries';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
RESET ROLE;

\echo 'push schema: all checks passed'
