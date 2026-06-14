-- Mock Clean WordPress database dump
CREATE TABLE `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL DEFAULT '',
  `user_pass` varchar(255) NOT NULL DEFAULT '',
  `user_nicename` varchar(50) NOT NULL DEFAULT '',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`)
);

INSERT INTO `wp_users` VALUES (1, 'site_admin', '$P$Babcdefghijklmnopqrstuvwxyz0123', 'admin', 'admin@mywordpresssite.com');
INSERT INTO `wp_users` VALUES (2, 'editor_alice', '$P$Babcdefghijklmnopqrstuvwxyz4567', 'alice', 'alice@mywordpresssite.com');
