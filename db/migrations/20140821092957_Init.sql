-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE EXTENSION "uuid-ossp";
CREATE TABLE event (
	id serial PRIMARY KEY,
	name varchar(255),
	auth_method varchar(255),
	auth_method_config json
);
CREATE UNIQUE INDEX event_name ON auth_event (name);

CREATE TABLE user (
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	event_id integer references event(id),
	status varchar(255),
	metadata json,
	CONSTRAINT "TB_Class_ID" PRIMARY KEY ("Id")
);

CREATE TABLE attempt (
	id serial PRIMARY KEY,
	user_id integer references user(id),
	status varchar(255),
	user_action varchar(255),
	credentials json
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE event;
DROP TABLE user;
DROP TABLE attempt;
