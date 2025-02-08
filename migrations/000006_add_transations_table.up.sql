CREATE TABLE IF NOT EXISTS transations (
    id bigserial PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    signature text NOT NULL UNIQUE,
    amount decimal(10, 2) NOT NULL
);