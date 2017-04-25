drop table if exists accounts;
create table accounts (
       'user' text not null unique,
       isAdministrator integer not null,
       email not null,
       home_address not null,
       phone_number not null,
       social_security not null,
       passwd text not null,
       salt text not null,
       totp_token text not null,
       image text not null,
       security_question not null,
       security_answer not null,
       attempts integer not null default 0
);
drop table if exists images;
create table images (
       title text not null,
       file text not null
);
-- populate default images
insert into images values ("apple", "apple.png");
insert into images values ("bird", "bird.png");
insert into images values ("building", "building.png");
insert into images values ("car", "car.png");
insert into images values ("guitar", "guitar.png");
insert into images values ("money", "money.png");
insert into images values ("mug", "mug.png");
insert into images values ("robot", "robot.png");
insert into images values ("stop sign", "stop-sign.png");
insert into images values ("tree", "tree.png");
