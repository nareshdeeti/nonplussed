CREATE TABLE users (
	user_id serial NOT NULL,
	username varchar NULL,
	email varchar NULL,
	roles varchar NULL,
	CONSTRAINT users_pk PRIMARY KEY (user_id)
);


ALTER TABLE users ADD usr_password varchar NULL;


