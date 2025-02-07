CREATE TABLE IF NOT EXISTS order_status (
    id bigint PRIMARY KEY,
    status text NOT NULL
);

INSERT INTO order_status(id, status)
VALUES (1, 'in_progress'),
       (2, 'delivered'), 
       (3, 'canceled');

CREATE TABLE IF NOT EXISTS orders (
    id bigserial PRIMARY KEY,
    created_at timestamp(0) with time zone NOT NULL DEFAULT NOW(),
    user_id bigint NOT NULL REFERENCES users(id),
    status_id bigint NOT NULL REFERENCES order_status(id) DEFAULT 1,
    completed_at timestamp(0) with time zone NOT NULL DEFAULT NOW(),
    version integer NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS order_items (
    id bigserial PRIMARY KEY,
    order_id bigserial NOT NULL REFERENCES orders(id),
    product_id bigint NOT NULL REFERENCES products(id),
    quantity bigint NOT NULL,
    price decimal (10, 2) NOT NULL
);