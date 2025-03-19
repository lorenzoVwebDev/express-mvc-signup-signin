const { errorLogger } = require('../middleware/logEvents.js')
const { errorCreator } = require('../configuration/commonFunctions.js')


const logsTest = async (req, res, next) => {
    if (!req.body) {
      res.status(400).send('invalid get request');
      next(errorCreator('invalid get request', 'error', __filename))
    }
    
}

module.exports = { logsTest }