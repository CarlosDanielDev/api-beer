create database beer;
use beer;
create table if not exists users(
	  id integer primary key not null auto_increment,
    user_name varchar(100) not null,
    passwd varchar(64) not null,
    email varchar(100) not null,
    tipo boolean not  null
);
create table if not exists cervejas(
	  id integer primary key not null auto_increment,
    nome varchar(100) not null,
    estilo varchar(45) not null,
    tipo varchar(45) not null,
    preco float(40) not null
