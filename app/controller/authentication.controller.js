//modules
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const striptags = require('striptags')
const dayjs = require('dayjs');
require('dotenv').config();
//models
const { mysqlQuery } = require('../configuration/mysqldb.config.js')
const { errorCreator } = require('../configuration/commonFunctions.js')
const model = require('../model/authentication.model.js')

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

  const result = await model.modelSignUp(newUser)

  return res.status(result[0]).json(result[1])

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

    const result = await model.modelSignIn(username, password)

    if (result[0] === 200) {
      return res.status(result[0])
      .cookie('refreshToken', result[2], {
        httpOnly: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000
      })
      .json({"accessToken": result[1]})
    }

    return res.status(result[0]).json(result[1])
    
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

    const result = await model.modelLogOut(refreshToken)
    
    res.clearCookie('refreshToken', refreshToken, {
      httpOnly: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000
    }).status(result[0]).json(result[1])
  } catch (error) {
    res.status(500).json({'response':'server-error'})
    next(errorCreator(error.message, 'error', __filename))
  }
}

const changePwd = async (req, res, next) => {
  try {
    let username = striptags(req.body['username'])
    let oldPassword = striptags(req.body['old-password'])
    let newPassword = striptags(req.body['new-password'])
    let confirmNewPassword = striptags(req.body['confirm-new-password'])

    if (!username || !oldPassword || !newPassword || !confirmNewPassword) return res.status(400).json({'response':'missing-credentials'});

    if (!(newPassword === confirmNewPassword)) return res.status(403).json({'response':'unequal-newpassword'});

    const result = await model.modelChangePwd({username, oldPassword, newPassword, confirmNewPassword})

    return res.status(result[0]).json(result[1])

  } catch (error) {
    res.status(500).json({'response':'server-error'})
    next(errorCreator(error.message, 'error', __filename))
  }
}

module.exports = {signUp, signIn, logOut, changePwd}