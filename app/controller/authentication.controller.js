//modules
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const striptags = require('striptags')
const dayjs = require('dayjs');
require('dotenv').config();
//models
const { mysqlQuery } = require('../configuration/mysqldb.config.js')
const { errorCreator } = require('../configuration/commonFunctions.js')

const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$/;


const signUp = async (req, res, next) => {
try {
  let { username, email, password } = req.body;

  if (!username || !email || !password) res.status(401).json({'response': 'missing-credentials'});
  
  username = striptags(username)
  email = emailRegex.test(striptags(email)) ? striptags(email) : null;
  password = passwordRegex.test(striptags(password)) ? striptags(password) : null;

  const newUser = {
    username, 
    email, 
    password
  }

  if (!Object.entries(newUser).every((value) => value[1])) res.status(400).json({'response': 'invalid-credentials'});

  const users = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['users'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  }) 

  for (const value of users) {
    if (value.username == username || value.email == email) {
      return res.status(409).json({'response':'user-duplicated'});
    }
  }

  const hashed = await bcrypt.hash(password, 10);
    
  newUser.password = hashed
  newUser.datestamp = dayjs().add(30, 'day').unix();



  const insert = await new Promise((resolve, reject) => {
    mysqlQuery('INSERT INTO ?? (username, email, password, datestamp) VALUES (?, ?, ?, ?)', ['users', newUser.username, newUser.email, newUser.password, newUser.datestamp], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })
  
  res.status(200).json({'response':'user-created'})


} catch (error) {
  res.status(500).json({'response':'server-error'})
  next(errorCreator(error.message, 'error', __filename))
}
}

const signIn = async (req, res, next) => {
  try {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({'message': 'missing-credentials'});
    
    username = striptags(username);
    password = striptags(password);

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

    if (!foundUser) return res.status(400).json({'response': 'not-found'})
    
    const currentUnix = dayjs().unix()
    
    if (currentUnix > foundUser.datestamp) return res.status(410).redirect('/authentication/changepwd');

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
        return res.status(200)
          .cookie('refreshToken', refreshToken, {
            httpOnly: true, maxAge: 24 * 60 * 60 * 1000
          })
          .json({"accessToken":accessToken})
      } else {
        foundUser.lastattempt = currentUnix;
        if (currentUnixMinus5>=lastattempt) {
          foundUser.attempts = 0;
        } else if (foundUser.attempts < 3) {
          foundUser.attempts += 1;
        }

        return res.status(401).json({'response':'wrong-password'})
      }
    } else {
      return res.status(401).json({"response":"attempts-excedeed"})
    }
  } catch (error) {
    res.status(500).json({'response':'server-error'})
    next(errorCreator(error.message, 'error', __filename))
  }
}

const logOut = async (req, res, next) => {
  try {
    const cookies = req.cookies;
    if (!cookies.refreshToken) return res.sendStatus(204);

    const refreshToken = cookies.refreshToken;

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

      res.clearCookie('refreshToken', refreshToken, {
        httpOnly: true, maxAge: 24 * 60 * 60 * 1000
      }).status(200).json({'response':'log-out'})

    } else {
      res.clearCookie('refreshToken', refreshToken, {
        httpOnly: true, maxAge: 24 * 60 * 60 * 1000
      }).status(200).json({'response':'log-out'})
    }
  } catch (error) {
    res.status(500).json({'response':'server-error'})
    next(errorCreator(error.message, 'error', __filename))
  }
}

module.exports = {signUp, signIn, logOut}