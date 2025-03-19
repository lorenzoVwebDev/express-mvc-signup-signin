const path = require('path')

const errorHandler = (err, req, res, next) => {
  console.log(err.message)
  res.sendFile(path.join(__dirname, '../', '../', 'public', '500.html'))
}

module.exports = errorHandler