# Table structure for table `log`
CREATE DATABASE syslog;

USE syslog;

CREATE TABLE logs (
host varchar(32) default NULL,
facility varchar(10) default NULL,
priority varchar(10) default NULL,
level varchar(10) default NULL,
tag varchar(10) default NULL,
date date default NULL,
time time default NULL,
program varchar(15) default NULL,
msg text,
seq int(10) unsigned NOT NULL auto_increment,
PRIMARY KEY (seq),
KEY host (host),
KEY seq (seq),
KEY program (program),
KEY time (time),
KEY date (date),
KEY priority (priority),
KEY facility (facility)
) TYPE=MyISAM;

GRANT ALL PRIVILEGES ON syslog.* TO syslog@localhost identified by 'syslog' with grant option;