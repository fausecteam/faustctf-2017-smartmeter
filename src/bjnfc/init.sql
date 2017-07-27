begin;

CREATE ROLE smartmeter with login;
REVOKE ALL ON DATABASE smartmeter FROM smartmeter;

CREATE TABLE users (
    id SERIAL,
    email varchar(50) NOT NULL,
    password char(60) NOT NULL,
    CONSTRAINT users_id PRIMARY KEY("id"),
    CONSTRAINT email UNIQUE(email)
);
GRANT SELECT, INSERT ON users TO smartmeter;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO smartmeter;

create table devices (
    id SERIAL,
    name varchar(20),
    CONSTRAINT devices_id PRIMARY KEY("id")
);
GRANT SELECT ON devices TO smartmeter;
GRANT SELECT ON SEQUENCE devices_id_seq TO smartmeter;

create table owners (
    device_id integer REFERENCES devices (id) NOT NULL,
    user_id integer REFERENCES users (id) NOT NULL,
    reason TEXT,
    CONSTRAINT id PRIMARY KEY("device_id")
);
GRANT SELECT, UPDATE, INSERT ON owners TO smartmeter;

INSERT INTO devices (name) VALUES
    ('smartmeter'),
    ('smartwatch'),
    ('doedel'),
    ('doodle'),
    ('toaster'),
    ('tempsense'),
    ('smartscale'),
    ('toilet'),
    ('alexa');

create table challenges (
    value char(32),
    expiry timestamp,
    CONSTRAINT val PRIMARY KEY ("value")
);
GRANT SELECT, INSERT, DELETE ON challenges TO smartmeter;

create extension pgcrypto;

commit;
