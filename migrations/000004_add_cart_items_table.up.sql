CREATE TABLE IF NOT EXISTS cart_items (
    id bigserial PRIMARY KEY,
    product_id bigint NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount integer NOT NULL,
    version integer NOT NULL
);

ALTER TABLE cart_items ADD CONSTRAINT unique_cart_item UNIQUE (product_id, user_id);