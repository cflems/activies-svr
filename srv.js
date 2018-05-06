const {APP_PORT, SQL_CFG, SECRET_KEY} = require('./cfg');
const Promise = require('bluebird');
const mysql = Promise.promisifyAll(require('mysql'));
const fs = Promise.promisifyAll(require('fs'));

const http = require('http');
const crypto = require('crypto');
const uuid = require('uuid/v4');
const WebSocketServer = require('ws').Server;

function query (qstr, fields) {
  return new Promise(function (resolve, reject) {
    let conn = pool.getConnection(function (err, conn) {
      if (err) return reject(err);
      conn.query(qstr, fields, function (err, result) {
        if (err) return reject(err);
        resolve(result);
        conn.release();
      });
    });
  });
}

function replyerr (emsg, client, reject) {
  try {
    client.send(JSON.stringify({
      'status': 'error',
      'message': emsg,
    }));
    if (reject) reject(emsg);
  } catch (e) {
    reject('Client disconnected while attempting to inform:', client._socket.remoteAddress);
  }
}

function hash_pass (pass) {
  return crypto.createHmac('sha256', SECRET_KEY).update(pass).digest('hex');
}

function attsend (obj, client, resolve, reject) {
  try {
    client.send(JSON.stringify(obj));
    resolve();
  } catch (e) {
    reject('Client disconnected while processing request.');
  }
}

function valauthkey (authkey) {
  return query('SELECT uid FROM authkeys WHERE authkey = ?', [authkey]).then(function (result) {
    if (result.length < 1) return Promise.reject('Authorization failed.');
    return Promise.resolve(result[0].uid);
  });
}

function addAuthKey (uid, client, resolve, reject) {
  let authkey = uuid();
  return query('INSERT INTO authkeys (uid, authkey) VALUES ?', [[[uid, authkey]]]).then(function (result) {
    if (result.affectedRows < 1) replyerr('Could not insert unique authkey.', client, reject);
    attsend({
      'status': 'ok',
      'authkey': authkey,
    }, client, resolve, reject);
  });
}

function process (dobj, client) {
  return new Promise(function (resolve, reject) {
    try {
      if (!dobj.action) return replyerr('Malformatted request: no action keyword.', client, reject);

      switch (dobj.action.trim().toLowerCase()) {
        case 'login':
          return query('SELECT id FROM users WHERE username = ? AND password = ? LIMIT 1', [dobj.uname, hash_pass(dobj.pass)]).then(function (result) {
            if (result.length < 1) return replyerr('Login failed.', client, reject);
            addAuthKey(result[0].id, client, resolve, reject);
          });
        case 'register':
          // TODO: verify emails?
          return query('SELECT 1 FROM users WHERE username = ? LIMIT 1', [dobj.uname]).then(function (result) {
            if (result.length > 0)
              return attsend({
                'status': 'error',
                'message': 'Username is taken.',
              }, client, resolve, reject);
            return query('INSERT INTO users (username, email, password) VALUES ?', [[[dobj.uname, dobj.email, hash_pass(dobj.pass)]]]).then(function (result) {
              if (result.affectedRows < 1) replyerr('Unable to insert user object.', client, reject);
              return addAuthKey(result.insertId, client, resolve, reject);
            });
          });
        case 'list':
          return valauthkey(dobj.authkey).then(function (uid) {
            return query('SELECT posts.id, posts.title, posts.description, posts.pic, users.username AS user FROM posts LEFT JOIN users ON posts.uid = users.id', []).then(function (result) {
              attsend(result, client, resolve, reject);
            });
            // TODO: zone code
          }).catch(function (e) {
            return replyerr(e, client, reject);
          });
        case 'post':
          return valauthkey(dobj.authkey).then(function (uid) {
            return query('INSERT INTO posts (uid, title, description, location) VALUES ?', [[[uid, dobj.title, dobj.description, dobj.location]]]).then(function (result) {
              if (result.affectedRows < 1) replyerr('Row could not be inserted.', client, reject);
              attsend({'status': 'ok'}, client, resolve, reject);
            });
          }).catch(function (e) {
            replyerr(e, client, reject);
          });
        case 'show':
          return valauthkey(dobj.authkey).then(function (uid) {
            return query('SELECT posts.id, posts.title, posts.location, posts.pic, posts.description, (SELECT COUNT(1) FROM likes WHERE likes.pid = posts.id) AS likes, EXISTS(SELECT 1 FROM likes WHERE likes.uid = ? AND likes.pid = posts.id) AS i_liked FROM posts WHERE posts.id = ? LIMIT 1', [uid, dobj.id]).then(function (result) {
              if (result.length < 1) return attsend({}, client, resolve, reject);
              attsend(result[0], client, resolve, reject);
            });
          }).catch(function (e) {
            replyerr(e, client, reject);
          });
        case 'like':
          return valauthkey(dobj.authkey).then(function (uid) {
            return query('INSERT INTO likes (uid, pid) VALUES ? ON DUPLICATE KEY UPDATE id=id', [[[uid, dobj.id]]]).then(function () {
              return query('SELECT COUNT(1) AS counter FROM likes WHERE pid = ?', [dobj.id]).then(function (result) {
                if (result.length < 1) return reject('Failed to retrieve like count for post.');
                return attsend({'status': 'liked', 'likes': result[0].counter}, client, resolve, reject);
              });
            });
          });
        case 'unlike':
          return valauthkey(dobj.authkey).then(function (uid) {
            return query('DELETE FROM likes WHERE uid = ? AND pid = ?', [uid, dobj.id]).then(function () {
              return query('SELECT COUNT(1) AS counter FROM likes WHERE pid = ?', [dobj.id]).then(function (result) {
                if (result.length < 1) return reject('Failed to retrieve like count for post.');
                return attsend({'status': 'unliked', 'likes': result[0].counter}, client, resolve, reject);
              });
            });
          });
        case 'myprof': // TODO: during beta, not implemented
        default:
          return replyerr('Unrecognized action keyword.', client, reject);
      }
    } catch (e) {
      return reject(e);
    }
  });
}

console.log('trying to create pool');
let pool = mysql.createPool(SQL_CFG);
console.log('created the pool');
let underlying_http = http.createServer(function (req, resp) {
  resp.writeHead(200);
  resp.end('Found.');
}).listen(APP_PORT);
let wss = new WebSocketServer({server: underlying_http});

wss.on('connection', function (client) {
  console.log('[INFO] Client connected:', client._socket.remoteAddress);
  client.on('message', function (msg) {
    let dobj;
    try {
      dobj = JSON.parse(msg);
    } catch (e) {
      replyerr('Malformatted request.', client);
    }
    process(dobj, client).catch(function (e) {
      console.warn('[WARN] Error while processing', client._socket.remoteAddress, ':', e);
    });
  });
  client.on('close', function () {
    console.log('[INFO] Client disconnected:', client._socket.remoteAddress);
  });
});
