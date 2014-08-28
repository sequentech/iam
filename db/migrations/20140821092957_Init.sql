-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE event (
	id serial PRIMARY KEY,
	name varchar(255),
	auth_method varchar(255),
	auth_method_config json
);
CREATE UNIQUE INDEX event_name ON event (name);

CREATE TABLE auth_user (
	id varchar(36) PRIMARY KEY,
	event_id integer REFERENCES event(id),
	status varchar(255),
	metadata json
);
CREATE UNIQUE INDEX auth_event_id ON auth_user (event_id);
CREATE UNIQUE INDEX auth_status ON auth_user (status);

CREATE TABLE attempt (
	id serial PRIMARY KEY,
	user_id varchar(36) REFERENCES auth_user(id),
	status varchar(255),
	user_action varchar(255),
	credentials json
);
CREATE UNIQUE INDEX attempt_user_id ON attempt (user_id);
CREATE UNIQUE INDEX attempt_status ON attempt (status);
CREATE UNIQUE INDEX attempt_user_action ON attempt (user_action);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE attempt;
DROP TABLE auth_user;
DROP TABLE event;
