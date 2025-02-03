CREATE TABLE IF NOT EXISTS users (
    id bigserial PRIMARY KEY,
    created_at timestamp(0) with time zone NOT NULL DEFAULT NOW(),
    name varchar(50) NOT NULL,
    email citext UNIQUE NOT NULL,
    password bytea NOT NULL,
    is_activated boolean NOT NULL,
    version integer NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS users_email_index ON users(email); 