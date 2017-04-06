drop table if exists accounts;
create table accounts (
       'user' text not null,
       isAdministrator integer not null,
       passwd text not null,
       salt text not null,
       totp_token text not null,
       image text not null,
       security_question not null,
       security_answer not null
);
-- TODO To consider: Is an administrator a type of user, or a different entity, in this model?
drop table if exists images;
create table images (
       title text not null
);
