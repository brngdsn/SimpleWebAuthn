create database SimpleWebAuthnDB;
create user SimpleWebAuthnDB_user with encrypted password :'password_variable';

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE invite_tokens (
    token_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    used BOOLEAN DEFAULT FALSE
);

CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_id INTEGER REFERENCES invite_tokens(token_id) ON DELETE SET NULL,
    credentialpublickey BYTEA NOT NULL,
    credentialid BYTEA NOT NULL UNIQUE,
    counter INTEGER NOT NULL,
    transports TEXT NOT NULL,
    CONSTRAINT unique_token_per_device UNIQUE (token_id)
);

INSERT INTO invite_tokens (user_id, token, created_at, expires_at, used) 
VALUES (1, '5e31570c.e0fx7Ebts34LC_fsfkR8Vg', NOW(), NOW() + INTERVAL '24 hours', FALSE);

grant all privileges on database SimpleWebAuthnDB to SimpleWebAuthnDB_user;
grant all privileges on all tables in schema public to SimpleWebAuthnDB_user;
grant usage, select on all sequences in schema public to SimpleWebAuthnDB_user;
