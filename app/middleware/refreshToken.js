
const jwt = require('jsonwebtoken');
const {mysqlQuery} = require('../configuration/mysqldb.config.js')

require('dotenv').config();

const refreshToken = async (req, res, next) => {
  const cookies = req.cookies

  if (!cookies.refreshToken) return res.status(401).json({"message":"unauthorized"})

  const refreshToken = cookies.refreshToken;

  const users = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['users'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  }) 

  const foundUser = users.find(user => {
    return user.refresh_token === refreshToken
  })

  if (!foundUser) return res.status(403).json({"message": "not-found"})

  jwt.verify(
    refreshToken, 
    process.env.REFRESH_TOKEN, 
    (err, decoded) => {
      if (err || foundUser.username !== decoded.username) return res.status(403).json({"message": err.message})
        const accessToken = jwt.sign(
          {"username": decoded.username},
          process.env.ACCESS_TOKEN,
          {expiresIn: 900}
        );

        return res.status(200).json({'accessToken': accessToken})

    })
}

module.exports = refreshToken
