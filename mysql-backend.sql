-- Add/Combine to JuneDNS Server database

CREATE TABLE IF NOT EXISTS `templates` (
  `id` int(11) unsigned NOT NULL auto_increment,
  `name` varchar(50) NOT NULL,
  `description` varchar(100) DEFAULT NULL,
  `is_default` tinyint(1) NOT NULL default '0',
  UNIQUE KEY `name` (`name`),
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `template_records` (
  `id` int(11) unsigned NOT NULL auto_increment,
  `template_id` int(11) unsigned NOT NULL,
  `name` varchar(255) NOT NULL,
  `type` varchar(10),
  `content` text,
  `ttl` int(11) unsigned NOT NULL DEFAULT '259200',
  PRIMARY KEY  (`id`),
  FOREIGN KEY (`template_id`) REFERENCES `templates` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) unsigned NOT NULL auto_increment,
  `code` varchar(25) NOT NULL default '',
  `passwd` varchar(200) binary NOT NULL default '',
  `name` varchar(50) DEFAULT NULL,
  `is_admin` tinyint(1) NOT NULL default '0',
  UNIQUE KEY `code` (`code`),
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `permissions` (
  `user_id` int(11) unsigned NOT NULL,
  `domain_id` int(11) unsigned NOT NULL,
  `readonly` tinyint(1) NOT NULL default '0',
  PRIMARY KEY  (`user_id`, `domain_id`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB;

INSERT IGNORE INTO templates SET id=1, name='Default DNS records', description='Normal DNS zone with MX on server', is_default=1;
INSERT IGNORE INTO templates SET id=2, name='Records for Google Workspace', description='DNS zone with MX for Google Workspace';

INSERT INTO template_records SET template_id=1, name='%d%', type='SOA', content='ns1.%m% info.%m% 3 10380 3600 604800 3600';
INSERT INTO template_records SET template_id=1, name='%d%', type='A', content='%ip4%';
INSERT INTO template_records SET template_id=1, name='%d%', type='AAAA', content='%ip6%';
INSERT INTO template_records SET template_id=1, name='%d%', type='NS', content='ns1.%m%';
INSERT INTO template_records SET template_id=1, name='%d%', type='NS', content='ns2.%m%';
INSERT INTO template_records SET template_id=1, name='www.%d%', type='CNAME', content='%d%';
INSERT INTO template_records SET template_id=1, name='%d%', type='MX', content='mail.%d% 10';
INSERT INTO template_records SET template_id=1, name='mail.%d%', type='A', content='%ip4%';
INSERT INTO template_records SET template_id=1, name='mail.%d%', type='AAAA', content='%ip6%';
INSERT INTO template_records SET template_id=1, name='%d%', type='TXT', content='v=spf1 mx -all';

INSERT INTO template_records SET template_id=2, name='%d%', type='SOA', content='ns1.%m% info.%m% 3 10380 3600 604800 3600';
INSERT INTO template_records SET template_id=2, name='%d%', type='A', content='%ip4%';
INSERT INTO template_records SET template_id=2, name='%d%', type='AAAA', content='%ip6%';
INSERT INTO template_records SET template_id=2, name='%d%', type='NS', content='ns1.%m%';
INSERT INTO template_records SET template_id=2, name='%d%', type='NS', content='ns2.%m%';
INSERT INTO template_records SET template_id=2, name='www.%d%', type='CNAME', content='%d%';
INSERT INTO template_records SET template_id=2, name='%d%', type='MX', content='aspmx.l.google.com 1';
INSERT INTO template_records SET template_id=2, name='%d%', type='MX', content='alt1.aspmx.l.google.com 5';
INSERT INTO template_records SET template_id=2, name='%d%', type='MX', content='alt2.aspmx.l.google.com 5';
INSERT INTO template_records SET template_id=2, name='%d%', type='MX', content='alt3.aspmx.l.google.com 10';
INSERT INTO template_records SET template_id=2, name='%d%', type='MX', content='alt4.aspmx.l.google.com 10';
INSERT INTO template_records SET template_id=2, name='%d%', type='TXT', content='v=spf1 a include:_spf.google.com -all';
