//modules
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const striptags = require('striptags')
const dayjs = require('dayjs');
require('dotenv').config();
//models
const { mysqlQuery } = require('../configuration/mysqldb.config.js')
//regex
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$/;

//----------------------functions---------------

const modelSignUp = async (newUser) => {
  const users = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['users'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  }) 

  for (const value of users) {
    if (value.username == newUser.username || value.email == newUser.email) {
      return [409, {'response':'user-duplicated'}];
    }
  }

  const hashed = await bcrypt.hash(newUser.password, 10);
    
  newUser.password = hashed
  newUser.datestamp = dayjs().add(30, 'day').unix();



  const insert = await new Promise((resolve, reject) => {
    mysqlQuery('INSERT INTO ?? (username, email, password, datestamp) VALUES (?, ?, ?, ?)', ['users', newUser.username, newUser.email, newUser.password, newUser.datestamp], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })
  
  return [200, {'response':'user-created'}]
}

const modelSignIn = async (username, password) => {
  const users = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['users'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  }) 

  const foundUser = users.find(user => {
    if (user.username == username || user.email == username) {
      return user;
    }
  })

  if (!foundUser) return [400, {'response': 'not-found'}]
  
  const currentUnix = dayjs().unix()
  
  if (currentUnix > foundUser.datestamp) return res.status(410).redirect('/authentication.view/changepwr.view.html');

  const currentUnixMinus5 = dayjs().subtract(5, 'minute').unix()
  if (foundUser.attempts < 3 || foundUser.lastattempt < currentUnixMinus5) {
    const match = await bcrypt.compare(password, foundUser.password);

    if (match) {
      const accessToken = jwt.sign(
        {"username": foundUser.username},
        process.env.ACCESS_TOKEN,
        {expiresIn: 900}
      )

      const refreshToken = jwt.sign(
        {"username": foundUser.username},
        process.env.REFRESH_TOKEN,
        {expiresIn: "1d"}
      )

      foundUser.validattempt = currentUnix;
      foundUser.lastattempt = currentUnix;
      foundUser.attempts = 0;
      foundUser.refresh_token = refreshToken;

      const update = await new Promise((resolve, reject) => {
        mysqlQuery("UPDATE users SET refresh_token = ?, attempts = ?, lastattempt = ?, validattempt = ? WHERE id = ?", [foundUser.refresh_token, foundUser.attempts, foundUser.lastattempt, foundUser.validattempt, foundUser.id], resolve, reject)
      }).then(data => data).catch(error => {
        throw new Error(error)
      })
//add the secure: true flag to .cookie to allow the cookies to travel only over https protocols
/*       return res.status(200)
        .cookie('refreshToken', refreshToken, {
          httpOnly: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000
        })
        .json({"accessToken":accessToken}) */

        return [200, accessToken, refreshToken];
    } else {
      foundUser.lastattempt = currentUnix;
      if (currentUnixMinus5>=lastattempt) {
        foundUser.attempts = 0;
      } else if (foundUser.attempts < 3) {
        foundUser.attempts += 1;
      }

      return [401, {'response':'wrong-password'}]
    }
  } else {
    return [401, {"response":"attempts-excedeed"}]
  }
}

const modelLogOut = async (refreshToken) => {
  const users = await new Promise((resolve, reject) => {
    mysqlQuery("SELECT * from ??", ['users'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  });

  const user = users.find(user => user.refresh_token == refreshToken);

  if (user) {
    user.refreshToken = null;

    const update = await new Promise((resolve, reject) => {
      mysqlQuery("UPDATE users SET refresh_token = ? WHERE id = ?", [user.refreshToken, user.id], resolve, reject)
    }).then(data => data).catch(error => {
      throw new Error(error)
    })

    return [200, {'response':'log-out'}]

  } else {
    return [200, {'response':'log-out'}]
  }
}

const modelChangePwd = async (credentials) => {
  const users = await new Promise((resolve, reject) => {
    mysqlQuery("SELECT * FROM ??", ['users'], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })

  const user = users.find(user =>  {
    if ((user.username == credentials.username) || (user.email == credentials.username)) {
      return user
    }
  })

  if (!user) return [401, {'response':'not-found'}]
  const match = await bcrypt.compare(credentials.oldPassword, user.password);
  if (match) {
    newPassword = passwordRegex.test(striptags(credentials.newPassword)) ? credentials.newPassword : null;

    if (!newPassword) return [400, {'response': 'invalid-password'}];
    const hash = await bcrypt.hash(newPassword, 10);
    
    user.password = hash;
    user.datestamp = dayjs().add(30, 'day').unix();
    user.attempts = 0;

    const update = await new Promise((resolve, reject) => {
      mysqlQuery("UPDATE users SET password = ?, datestamp = ?, attempts = ? WHERE id = ?", [user.password, user.datestamp, user.attempts, user.id], resolve, reject)
    }).then(data => data).catch(error => {
      throw new Error(error)
    })

    return [200, {'response': 'updated-password'}]

  } else {
    return [401, {'response':'wrong-password'}]
  }
}

module.exports = { modelChangePwd, modelSignUp, modelLogOut, modelSignIn }