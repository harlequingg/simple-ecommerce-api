CREATE TABLE IF NOT EXISTS tokens(
    id bigserial PRIMARY KEY,
    hash bytea NOT NULL,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamp(0) with time zone NOT NULL,
    scope text NOT NULL  
);