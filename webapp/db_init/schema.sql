drop table if exists accounts;
create table passwords (
       id integer primary key autoincrement,
       'user' text not null
       passwd text not null
       totp_token text not null
       image text not null
       security_question not null
       security_answer not null
);
-- TODO To consider: Is an administrator a type of user, or a different entity, in this model?
