CREATE TABLE likes (
  id INT(255) NOT NULL PRIMARY KEY AUTO_INCREMENT,
  uid INT(255) NOT NULL,
  pid INT(255) NOT NULL,
  UNIQUE(uid, pid)
);
