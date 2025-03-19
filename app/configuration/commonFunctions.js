const path = require('path')

const errorCreator = (message, type, filename) => {
  const newError = new Error(message);
  newError.fileName = path.basename(filename)
  newError.type = type
  return newError
}

module.exports = {errorCreator}