const jwt = require('jsonwebtoken');
require('dotenv').config();
const { errorCreator } = require('../configuration/commonFunctions.js')

const refreshToken = require('./refreshToken.js')

const veirifyJWT = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader && !req.cookies.refreshToken) return res.status(401).json({'message':'unauthorized'});
    
    if (authHeader?.startsWith('Bearer ')) {
      const accessToken = authHeader.split(' ')[1];
        jwt.verify(accessToken, process.env.ACCESS_TOKEN,
          (err, decoded) => {
            if (err) {
              refreshToken(req, res);
            } else {
              req.username = decoded
              next()
            }
          }
        )
    } else {
      refreshToken(req, res);
    }
  } catch (error) {
    res.status(500).json({'message':'server-error'})
    next(errorCreator(error.message, 'error', __filename))
  }
}

module.exports = veirifyJWT 