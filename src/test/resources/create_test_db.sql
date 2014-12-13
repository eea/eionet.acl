
DROP TABLE IF EXISTS `acl_rows`;
CREATE TABLE `acl_rows` (
  `ACL_ID` int(11) NOT NULL default '0',
  `TYPE` varchar(100) NOT NULL default 'object',
  `ENTRY_TYPE` varchar(100) NOT NULL default 'user',
  `PRINCIPAL` char(16) NOT NULL default '',
  `PERMISSIONS` char(255) NOT NULL default '',
  `STATUS` int(1) NOT NULL default '0',
  PRIMARY KEY  (`ACL_ID`,`TYPE`,`ENTRY_TYPE`,`PRINCIPAL`,`STATUS`)
);

DROP TABLE IF EXISTS `acls`;
CREATE TABLE `acls` (
  `ACL_ID` int(11) NOT NULL auto_increment,
  `ACL_NAME` varchar(100) NOT NULL default '',
  `PARENT_NAME` varchar(100) default NULL,
  `OWNER` varchar(255) NOT NULL default '',
  `DESCRIPTION` varchar(255) default '',
  PRIMARY KEY  (`ACL_ID`),
  UNIQUE KEY `ACL_NAME` (`ACL_NAME`,`PARENT_NAME`)
);