const bcrypt = require('bcrypt');
const { mysqlQuery } = require('../configuration/mysqldb.config.js')
const { errorCreator } = require('../configuration/commonFunctions.js')
const striptags = require('striptags')
const dayjs = require('dayjs')
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$/;


const signUp = async (req, res, next) => {
try {
  let { username, email, password } = req.body;

  if (!username || !email || !password) res.status(401).json({'message': 'missing-credentials'});
  
  username = striptags(username)
  email = emailRegex.test(striptags(email)) ? striptags(email) : null;
  password = passwordRegex.test(striptags(password)) ? striptags(password) : null;

  const newUser = {
    username, 
    email, 
    password
  }

  if (!Object.entries(newUser).every((value) => value[1])) res.status(400).json({'message': 'invalid-credentials'});

  const users = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['users'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  }) 

  for (const value of users) {
    if (value.username == username || value.email == email) {
      return res.status(409).json({'message':'user-duplicated'});
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
  
  res.status(200).json({'message':'user-created'})


} catch (error) {
  res.status(500).json({'message':'server-error'})
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

    if (!foundUser) return res.status(400).json({'message': 'not-found'})

      console.log(foundUser)
    
    const currentUnix = dayjs().unix()
    
    if (currentUnix > foundUser.datestamp) return res.status(410).redirect('/authentication/changepwd');

    const currentUnixMinus5 = dayjs().subtract(5, 'minute').unix()
    if (foundUser.attempts <= 3 || foundUser.lastattempt < currentUnixMinus5) {
      const match = await bcrypt.compare(password, foundUser.password);

      if (match) {
        foundUser.validattempt = currentUnix;
        foundUser.lastattempt = currentUnix;
        foundUser.attempts = 0;
        //jwt
        const update = await new Promise((resolve, reject) => {
          mysqlQuery("UPDATE users SET attempts = ?, lastattempt = ?, validattempt = ? WHERE id = ?", [foundUser.attempts, foundUser.lastattempt, foundUser.validattempt, foundUser.id], resolve, reject)
        }).then(data => data).catch(error => {
          throw new Error(error)
        })

        res.status(200).json({"message":"send-token"})
      } else {
        foundUser.lastattempt = currentUnix;
        if (currentUnixMinus5>=lastattempt) {
          foundUser.attempts = 0;
        } else if (foundUser.attempts < 3) {
          foundUser.attempts += 1;
        }
      }
    } else {
      return res.status(401).json({"message":"attempts-excedeed"})
    }



  } catch (error) {
    res.status(500).json({'message':'server-error'})
    next(errorCreator(error.message, 'error', __filename))
  }
}

module.exports = {signUp, signIn}