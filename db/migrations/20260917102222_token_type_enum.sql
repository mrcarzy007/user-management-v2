-- migrate:up
CREATE TYPE token_type AS ENUM (
    'email_verification',
    'password_reset',
    'email_change'
);

ALTER TABLE user_action_tokens
    ALTER COLUMN token_type TYPE token_type 
    USING token_type::token_type;

-- migrate:down
ALTER TABLE user_action_tokens
ALTER COLUMN token_type TYPE text;

DROP TYPE token_type;