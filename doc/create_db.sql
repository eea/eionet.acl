--
-- MySQL syntax
--
DROP TABLE IF EXISTS ACL_ROWS;

CREATE TABLE ACL_ROWS (
  ACL_ID int(11) NOT NULL default '0',
  TYPE enum('object','doc','dcc') NOT NULL default 'object',
  ENTRY_TYPE enum('owner','user','localgroup','other','foreign','unauthenticated','authenticated','mask') NOT NULL default 'user',
  PRINCIPAL char(16) NOT NULL default '',
  PERMISSIONS char(255) NOT NULL default '',
  STATUS int(1) NOT NULL default '0',
  PRIMARY KEY  (ACL_ID,TYPE,ENTRY_TYPE,PRINCIPAL,STATUS)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS ACLS;

CREATE TABLE ACLS (
  ACL_ID int(11) NOT NULL auto_increment,
  ACL_NAME varchar(100) NOT NULL default '',
  PARENT_NAME varchar(100) default NULL,
  OWNER varchar(255) NOT NULL default '',
  DESCRIPTION varchar(255) default '',
  PRIMARY KEY  (ACL_ID),
  UNIQUE KEY ACL_NAME (ACL_NAME,PARENT_NAME)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
