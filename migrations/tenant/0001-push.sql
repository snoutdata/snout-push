-- The push schema in a project's database: its devices, topics, the queue and the delivery log.
--
-- Who may notify whom is decided HERE, once, by the project's own row-level security when a row is
-- inserted into push.messages. The sender expands and delivers what was already allowed; it never
-- decides access itself (docs/cloud/PUSH.md, P8).
--
-- The schema is expected to exist already, owned by the role the sender connects as, so that role
-- needs no CREATE on the database. Role names come from the settings the runner sets first
-- (push.anon_role, push.authenticated_role, push.service_role), and with push.install_roles = 'true'
-- the three API roles are created when missing (tests and self-hosting).
--
-- Nothing here needs the auth schema: a project may switch push on before, or without, auth. The
-- caller is read from the JWT claims the server sets for the transaction (push.uid()), and the link
-- to auth.users is made by push.link_auth(), which the sender calls on every registration.

DO $$
DECLARE
	anon text := coalesce(nullif(current_setting('push.anon_role', true), ''), 'anon');
	authed text := coalesce(nullif(current_setting('push.authenticated_role', true), ''), 'authenticated');
	service text := coalesce(nullif(current_setting('push.service_role', true), ''), 'service_role');
BEGIN
	IF coalesce(current_setting('push.install_roles', true), 'false') = 'true' THEN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = anon) THEN
			EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT', anon);
		END IF;
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = authed) THEN
			EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT', authed);
		END IF;
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = service) THEN
			EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT BYPASSRLS', service);
		END IF;
	END IF;
END
$$;

-- The caller: the `sub` of the JWT claims the server set for this transaction, or NULL for an
-- anonymous caller or a `sub` that is not a uuid. Never an error, so a policy using it never
-- turns a bad token into a failed query instead of a refused row.
CREATE FUNCTION push.uid() RETURNS uuid
LANGUAGE sql STABLE
AS $$
	SELECT CASE WHEN sub ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
		THEN sub::uuid END
	FROM (SELECT nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub' AS sub) AS claims
$$;

-- One row per project: how long the log is kept and how devices behave.
CREATE TABLE push.settings (
	id boolean PRIMARY KEY DEFAULT true CHECK (id),
	-- Delivery rows and finished messages older than this are pruned (PUSH.md, PQ3).
	retention_days integer NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650),
	-- A device not seen for this long is disabled (FCM's own staleness rule is a month).
	stale_device_days integer NOT NULL DEFAULT 30 CHECK (stale_device_days BETWEEN 1 AND 3650),
	-- When a second user registers a token already registered to someone else: false (the
	-- default) moves the device to the new user, so a shared phone stops notifying its previous
	-- owner; true keeps both (an app with account switching). PUSH.md, A2.
	shared_devices boolean NOT NULL DEFAULT false,
	-- Whether a caller who is not signed in may register a device (a web page's subscribers).
	anonymous_devices boolean NOT NULL DEFAULT false,
	-- Seconds a provider may hold a message when the sender gives no ttl. NULL: each provider's own.
	default_ttl integer CHECK (default_ttl >= 0)
);
INSERT INTO push.settings DEFAULT VALUES;

CREATE TABLE push.devices (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	-- NULL: a device registered without signing in (settings.anonymous_devices).
	user_id uuid,
	transport text NOT NULL CHECK (transport IN ('apns', 'fcm', 'web')),
	-- What the token is for: an app installation, or one Live Activity on an iPhone (A1).
	kind text NOT NULL DEFAULT 'device' CHECK (kind IN ('device', 'live_activity')),
	-- The APNs device token (hex), the FCM registration token, or the Web Push endpoint URL.
	token text NOT NULL CHECK (length(token) BETWEEN 1 AND 4096),
	-- Web Push only: the browser's key and auth secret (base64url), and which of the project's
	-- VAPID keys it subscribed under, since a subscription can only ever take that key (A8).
	web_p256dh text,
	web_auth text,
	vapid_key_id text,
	-- APNs only: which of Apple's environments the token belongs to (a development build's token
	-- is valid only against the sandbox).
	apns_environment text CHECK (apns_environment IN ('production', 'sandbox')),
	-- The app: an APNs bundle id, or an FCM app id. NULL: the project's default.
	app text,
	locale text,
	created_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	disabled_at timestamptz,
	disabled_reason text,
	CHECK ((transport = 'web') = (web_p256dh IS NOT NULL AND web_auth IS NOT NULL)),
	CHECK ((transport = 'apns') = (apns_environment IS NOT NULL)),
	CHECK (kind = 'device' OR transport = 'apns')
);
-- A2: one row per user per token, anonymous rows included (NULLS NOT DISTINCT, Postgres 15+).
CREATE UNIQUE INDEX devices_user_token ON push.devices (user_id, transport, token) NULLS NOT DISTINCT;
CREATE INDEX devices_token ON push.devices (transport, token);
CREATE INDEX devices_live_user ON push.devices (user_id) WHERE disabled_at IS NULL;

CREATE TABLE push.topics (
	name text PRIMARY KEY CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
	description text,
	created_at timestamptz NOT NULL DEFAULT now()
);

-- A member is a user (every device of theirs) or a single device (an anonymous subscriber).
CREATE TABLE push.topic_members (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	topic text NOT NULL REFERENCES push.topics (name) ON DELETE CASCADE ON UPDATE CASCADE,
	user_id uuid,
	device_id uuid REFERENCES push.devices (id) ON DELETE CASCADE,
	created_at timestamptz NOT NULL DEFAULT now(),
	CHECK (num_nonnulls(user_id, device_id) = 1)
);
CREATE UNIQUE INDEX topic_members_user ON push.topic_members (topic, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX topic_members_device ON push.topic_members (topic, device_id) WHERE device_id IS NOT NULL;
CREATE INDEX topic_members_by_user ON push.topic_members (user_id) WHERE user_id IS NOT NULL;

-- The queue. A row is a request to notify; the sender claims it when `send_at` is due.
CREATE TABLE push.messages (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	-- Exactly one target.
	target_user_ids uuid[],
	target_topic text,
	target_device_ids uuid[],
	-- The notification, in the shape `snout-push` validates (title, body, data, badge, sound,
	-- thread, image, url, background, and per-transport apns / fcm / web passthrough).
	notification jsonb NOT NULL CHECK (jsonb_typeof(notification) = 'object'),
	send_at timestamptz NOT NULL DEFAULT now(),
	ttl integer CHECK (ttl >= 0),
	priority text NOT NULL DEFAULT 'high' CHECK (priority IN ('high', 'normal')),
	collapse_key text CHECK (length(collapse_key) BETWEEN 1 AND 64),
	created_by uuid DEFAULT push.uid(),
	created_at timestamptz NOT NULL DEFAULT now(),
	-- queued → sending → sent (every device accepted) | partial (some) | failed (none);
	-- refused (never sent, with the reason in status_detail); cancelled (by the customer).
	-- One dead device never makes a message `failed` on its own.
	status text NOT NULL DEFAULT 'queued'
		CHECK (status IN ('queued', 'sending', 'sent', 'partial', 'failed', 'refused', 'cancelled')),
	status_detail text,
	claimed_at timestamptz,
	-- When the targets were turned into delivery rows. A claim older than a few minutes with no
	-- expansion is a sender that died mid-claim, and is taken again; once expanded, the delivery
	-- rows carry the work and the message is never expanded twice.
	expanded_at timestamptz,
	finished_at timestamptz,
	CHECK (num_nonnulls(target_user_ids, target_topic, target_device_ids) = 1),
	CHECK (cardinality(target_user_ids) BETWEEN 1 AND 10000),
	CHECK (cardinality(target_device_ids) BETWEEN 1 AND 10000)
);
CREATE INDEX messages_due ON push.messages (send_at) WHERE status = 'queued';
CREATE INDEX messages_created_by ON push.messages (created_by);

-- The log: one row per device per message (unique, so a retried claim cannot deliver twice).
CREATE TABLE push.deliveries (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	message_id bigint NOT NULL REFERENCES push.messages (id) ON DELETE CASCADE,
	-- NULL once the device is deleted; the row stays for the log's retention.
	device_id uuid REFERENCES push.devices (id) ON DELETE SET NULL,
	transport text NOT NULL,
	-- accepted is the PROVIDER's acceptance, never "delivered" (P11): that is received_at, which
	-- only the app reports.
	status text NOT NULL DEFAULT 'pending'
		CHECK (status IN ('pending', 'accepted', 'failed', 'unregistered', 'refused')),
	provider_id text,
	error text,
	attempts integer NOT NULL DEFAULT 0,
	next_attempt_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	accepted_at timestamptz,
	received_at timestamptz,
	opened_at timestamptz,
	UNIQUE (message_id, device_id)
);
CREATE INDEX deliveries_retry ON push.deliveries (next_attempt_at) WHERE status = 'pending';
CREATE INDEX deliveries_device ON push.deliveries (device_id);

-- `created_by` is the caller, whatever the insert said: a user a policy lets send cannot send as
-- somebody else. A caller with no `sub` (the service role) keeps what it wrote.
CREATE FUNCTION push.stamp_sender() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF push.uid() IS NOT NULL THEN
		NEW.created_by := push.uid();
	END IF;
	NEW.status := 'queued';
	NEW.status_detail := NULL;
	NEW.claimed_at := NULL;
	NEW.expanded_at := NULL;
	NEW.finished_at := NULL;
	RETURN NEW;
END
$$;
CREATE TRIGGER messages_stamp BEFORE INSERT ON push.messages
	FOR EACH ROW EXECUTE FUNCTION push.stamp_sender();

-- Wakes the sender's LISTEN when there is something to do now. A future `send_at` is found by the
-- sender's own timer, so it needs no notification.
CREATE FUNCTION push.notify_queued() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF NEW.status = 'queued' AND NEW.send_at <= now() THEN
		PERFORM pg_notify('snout_push', NEW.id::text);
	END IF;
	RETURN NULL;
END
$$;
CREATE TRIGGER messages_notify AFTER INSERT ON push.messages
	FOR EACH ROW EXECUTE FUNCTION push.notify_queued();

-- A send, from SQL. An ordinary insert run AS THE CALLER, so the insert policies on push.messages
-- decide whether this caller may send this: the whole of push's access control is those policies.
CREATE FUNCTION push.send(
	notification jsonb,
	user_ids uuid[] DEFAULT NULL,
	topic text DEFAULT NULL,
	device_ids uuid[] DEFAULT NULL,
	send_at timestamptz DEFAULT now(),
	ttl integer DEFAULT NULL,
	priority text DEFAULT 'high',
	collapse_key text DEFAULT NULL
) RETURNS bigint
LANGUAGE sql VOLATILE SECURITY INVOKER
AS $$
	INSERT INTO push.messages
		(notification, target_user_ids, target_topic, target_device_ids, send_at, ttl, priority, collapse_key)
	VALUES (notification, user_ids, topic, device_ids, send_at, ttl, priority, collapse_key)
	RETURNING id
$$;

-- Registering a device. SECURITY DEFINER because moving a token away from its previous owner (A2)
-- touches a row the caller cannot see; everything else it does is bounded to the caller's own row.
CREATE FUNCTION push.register_device(
	transport text,
	token text,
	web_p256dh text DEFAULT NULL,
	web_auth text DEFAULT NULL,
	vapid_key_id text DEFAULT NULL,
	apns_environment text DEFAULT NULL,
	app text DEFAULT NULL,
	locale text DEFAULT NULL,
	kind text DEFAULT 'device'
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = ''
AS $$
-- The parameters share the columns' names; where both could be meant (the ON CONFLICT target),
-- the column is. Every other use of a parameter is qualified or has no column in scope.
#variable_conflict use_column
DECLARE
	caller uuid := push.uid();
	settings push.settings;
	device uuid;
BEGIN
	SELECT * INTO settings FROM push.settings;
	IF caller IS NULL AND NOT settings.anonymous_devices THEN
		RAISE EXCEPTION 'Sign in to register a device (this project does not take anonymous devices).'
			USING ERRCODE = '42501';
	END IF;
	IF NOT settings.shared_devices THEN
		DELETE FROM push.devices d
		WHERE d.transport = register_device.transport AND d.token = register_device.token
			AND d.user_id IS DISTINCT FROM caller;
	END IF;
	INSERT INTO push.devices AS d
		(user_id, transport, kind, token, web_p256dh, web_auth, vapid_key_id, apns_environment, app, locale)
	VALUES
		(caller, transport, kind, token, web_p256dh, web_auth, vapid_key_id, apns_environment, app, locale)
	ON CONFLICT (user_id, transport, token) DO UPDATE SET
		kind = excluded.kind,
		web_p256dh = excluded.web_p256dh,
		web_auth = excluded.web_auth,
		vapid_key_id = excluded.vapid_key_id,
		apns_environment = excluded.apns_environment,
		app = excluded.app,
		locale = excluded.locale,
		last_seen_at = now(),
		disabled_at = NULL,
		disabled_reason = NULL
	RETURNING d.id INTO device;
	RETURN device;
END
$$;

-- An app's report that a notification arrived or was opened (P11). Only for the caller's own device.
CREATE FUNCTION push.report_receipt(delivery_id bigint, event text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
	caller uuid := push.uid();
	found_row boolean;
BEGIN
	IF event NOT IN ('received', 'opened') THEN
		RAISE EXCEPTION 'A receipt is "received" or "opened".' USING ERRCODE = '22023';
	END IF;
	UPDATE push.deliveries l SET
		received_at = coalesce(l.received_at, now()),
		opened_at = CASE WHEN event = 'opened' THEN coalesce(l.opened_at, now()) ELSE l.opened_at END
	FROM push.devices d
	WHERE l.id = delivery_id AND d.id = l.device_id
		AND (d.user_id = caller OR (d.user_id IS NULL AND caller IS NULL))
	RETURNING true INTO found_row;
	RETURN coalesce(found_row, false);
END
$$;

-- Adds the foreign keys to auth.users once auth exists (a project may switch push on first), so a
-- deleted user takes their devices and memberships along. Idempotent; the sender calls it on every
-- registration of the project.
CREATE FUNCTION push.link_auth() RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
BEGIN
	IF to_regclass('auth.users') IS NULL THEN
		RETURN;
	END IF;
	IF NOT EXISTS (SELECT FROM pg_constraint WHERE conname = 'devices_user_fk' AND conrelid = 'push.devices'::regclass) THEN
		DELETE FROM push.devices d WHERE d.user_id IS NOT NULL
			AND NOT EXISTS (SELECT FROM auth.users u WHERE u.id = d.user_id);
		ALTER TABLE push.devices ADD CONSTRAINT devices_user_fk
			FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE;
	END IF;
	IF NOT EXISTS (SELECT FROM pg_constraint WHERE conname = 'topic_members_user_fk' AND conrelid = 'push.topic_members'::regclass) THEN
		DELETE FROM push.topic_members m WHERE m.user_id IS NOT NULL
			AND NOT EXISTS (SELECT FROM auth.users u WHERE u.id = m.user_id);
		ALTER TABLE push.topic_members ADD CONSTRAINT topic_members_user_fk
			FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE;
	END IF;
END
$$;

-- The project's own APNs key, Firebase service account and VAPID keys: in the project's database,
-- beside the devices they send to, and nowhere else (docs/cloud/PUSH.md, P2 as reversed). `value`
-- is the sender's own shape for that kind; `summary` is what may be shown (ids, names, public keys).
--
-- Readable by the table's owner, the sender's role, and by NOBODY else: not anon, not
-- authenticated, and not the service role either, even though it bypasses row-level security,
-- because a grant is what it lacks. Keys go in through `/push/v1/credentials` (which proves them
-- first) and never come back out; `push.credential_summaries()` is what a screen reads.
CREATE TABLE push.credentials (
	kind text PRIMARY KEY CHECK (kind IN ('apns', 'fcm', 'vapid')),
	value jsonb NOT NULL CHECK (jsonb_typeof(value) = 'object'),
	summary jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(summary) = 'object'),
	updated_at timestamptz NOT NULL DEFAULT now()
);

-- A running sender reloads its keys when they change, rather than being restarted for it.
CREATE FUNCTION push.notify_credentials() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	PERFORM pg_notify('snout_push_credentials', coalesce(NEW.kind, OLD.kind));
	RETURN NULL;
END
$$;
CREATE TRIGGER credentials_notify AFTER INSERT OR UPDATE OR DELETE ON push.credentials
	FOR EACH ROW EXECUTE FUNCTION push.notify_credentials();

CREATE FUNCTION push.credential_summaries() RETURNS TABLE (kind text, summary jsonb, updated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
	SELECT c.kind, c.summary, c.updated_at FROM push.credentials c ORDER BY c.kind
$$;

-- Row-level security: the defaults. A customer widens them with ordinary policies, in SQL.
ALTER TABLE push.settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE push.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE push.topics ENABLE ROW LEVEL SECURITY;
ALTER TABLE push.topic_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE push.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE push.deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE push.credentials ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE
	anon text := coalesce(nullif(current_setting('push.anon_role', true), ''), 'anon');
	authed text := coalesce(nullif(current_setting('push.authenticated_role', true), ''), 'authenticated');
	service text := coalesce(nullif(current_setting('push.service_role', true), ''), 'service_role');
BEGIN
	EXECUTE format('GRANT USAGE ON SCHEMA push TO %I, %I, %I', anon, authed, service);
	EXECUTE format('GRANT ALL ON ALL TABLES IN SCHEMA push TO %I', service);
	-- Except the keys: see push.credentials.
	EXECUTE format('REVOKE ALL ON push.credentials FROM PUBLIC, %I, %I, %I', anon, authed, service);
	EXECUTE format('REVOKE ALL ON FUNCTION push.credential_summaries() FROM PUBLIC');
	EXECUTE format('GRANT EXECUTE ON FUNCTION push.credential_summaries() TO %I', service);
	EXECUTE format('GRANT ALL ON ALL SEQUENCES IN SCHEMA push TO %I', service);
	EXECUTE format('GRANT SELECT, UPDATE, DELETE ON push.devices TO %I', authed);
	EXECUTE format('GRANT SELECT, INSERT, DELETE ON push.topic_members TO %I', authed);
	EXECUTE format('GRANT SELECT ON push.topics TO %I', authed);
	-- INSERT is granted so a customer's policy CAN let users send; with no policy, none may.
	EXECUTE format('GRANT SELECT, INSERT, UPDATE ON push.messages TO %I', authed);
	EXECUTE format('GRANT SELECT ON push.deliveries TO %I', authed);
	EXECUTE format('REVOKE ALL ON FUNCTION push.link_auth() FROM PUBLIC');
	EXECUTE format('GRANT EXECUTE ON FUNCTION push.link_auth() TO %I', service);

	-- A signed-in user's own devices: read, rename (locale), remove. Registering is
	-- push.register_device(), so nobody inserts a device row by hand under someone else's id.
	EXECUTE format('CREATE POLICY devices_own ON push.devices FOR SELECT TO %I USING (user_id = push.uid())', authed);
	EXECUTE format('CREATE POLICY devices_own_update ON push.devices FOR UPDATE TO %I USING (user_id = push.uid()) WITH CHECK (user_id = push.uid())', authed);
	EXECUTE format('CREATE POLICY devices_own_delete ON push.devices FOR DELETE TO %I USING (user_id = push.uid())', authed);

	-- Topics are listed to signed-in users; a user joins and leaves for themselves.
	EXECUTE format('CREATE POLICY topics_read ON push.topics FOR SELECT TO %I USING (true)', authed);
	EXECUTE format('CREATE POLICY topic_members_own ON push.topic_members FOR SELECT TO %I USING (user_id = push.uid())', authed);
	EXECUTE format('CREATE POLICY topic_members_join ON push.topic_members FOR INSERT TO %I WITH CHECK (user_id = push.uid())', authed);
	EXECUTE format('CREATE POLICY topic_members_leave ON push.topic_members FOR DELETE TO %I USING (user_id = push.uid())', authed);

	-- Messages: nobody but the service role may send until the customer writes a policy. A
	-- sender sees and may cancel what they sent.
	EXECUTE format('CREATE POLICY messages_own ON push.messages FOR SELECT TO %I USING (created_by = push.uid())', authed);
	EXECUTE format($p$CREATE POLICY messages_cancel ON push.messages FOR UPDATE TO %I
		USING (created_by = push.uid() AND status = 'queued') WITH CHECK (created_by = push.uid() AND status = 'cancelled')$p$, authed);

	-- The log of what reached a user's own devices.
	EXECUTE format('CREATE POLICY deliveries_own ON push.deliveries FOR SELECT TO %I
		USING (EXISTS (SELECT FROM push.devices d WHERE d.id = device_id AND d.user_id = push.uid()))', authed);
END
$$;
