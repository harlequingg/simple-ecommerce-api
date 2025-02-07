CREATE TABLE IF NOT EXISTS products (
    id bigserial PRIMARY KEY,
    created_at timestamp(0) with time zone NOT NULL DEFAULT NOW(),
    updated_at timestamp(0) with time zone NOT NULL DEFAULT NOW(),
    name varchar(50) NOT NULL,
    description text NOT NULL,
    price decimal(10, 2) NOT NULL,
    quantity bigint NOT NULL,
    version integer NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS products_name_index ON products USING GIN (to_tsvector('simple', name));
CREATE INDEX IF NOT EXISTS products_description_index ON products USING GIN (to_tsvector('simple', description));