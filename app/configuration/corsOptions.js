const path = require('path')
const { errorCreator } = require('./commonFunctions.js')

const whiteList = ['https://www.yoursite.com'];
const { corsLogger } = require('../middleware/logEvents.js')

const corsOptions = {
  origin: (origin, callback) => {
    if (whiteList.indexOf(origin) !== -1 || !origin) {
      callback(null, true)
    } else {
      callback(errorCreator(`${origin} Not Allowed By Cors`, 'cors', __filename));
    }
  },
  allowedHeaders: ['project-type','Content-type'],
    exposedHeaders: ['project-type', 'Content-type'],
    credentials: true,
    maxAge: 10000,
    optionsSuccessStatus: 204
}

module.exports = corsOptions



















/* const whitelist = ['http://www.yoursite.com'];
const {corsLogger} = require('../middleware/logEvents.js')

const corsOptions = {
  origin: (origin, callback) => {
    if (whitelist.indexOf(origin) != -1) {
      corsLogger(`${origin} allowed by CORS`);
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'))
      corsLogger(`${origin} NOT allowed by CORS`);
    }
  },
  optionSuccessStatus: 200
}

module.exports = corsOptions */