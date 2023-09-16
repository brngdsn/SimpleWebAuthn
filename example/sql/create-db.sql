create database SimpleWebAuthnDB;
create user SimpleWebAuthnDB_user with encrypted password :'password_variable';

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    credentialpublickey BYTEA NOT NULL,
    credentialid BYTEA NOT NULL UNIQUE,
    counter INTEGER NOT NULL,
    transports TEXT NOT NULL
);

grant all privileges on database SimpleWebAuthnDB to SimpleWebAuthnDB_user;
grant all privileges on all tables in schema public to SimpleWebAuthnDB_user;
grant usage, select on all sequences in schema public to SimpleWebAuthnDB_user;
