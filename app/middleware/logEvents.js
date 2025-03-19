const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const {v4: uuid} = require('uuid')
const { format } = require('date-fns');

async function logEvents(msg, type) {
  const dateEvent = `${format(new Date(), 'yyyyMMdd\tHH:mm:ss')}`
  const logItem = `${dateEvent}\t${type}\t${uuid()}\t${msg}\n`
  try {
    if (!fs.existsSync(path.join(__dirname, '../', '../','logs'))) {
      await fsPromises.mkdir(path.join(__dirname, '../','../','logs'), (err) => {
        if (err) throw new Error()
      })
    }
    await fsPromises.appendFile(path.join(__dirname, '../','../', 'logs', `${type}Logs.log`), logItem) 
  } catch (err) {
    console.error(err);
  }
} 

const requestLogger = async (req, res, next) => {
  await logEvents(`${req.method}\t${req.headers.origin}\t${req.url}`, 'request');
  next();
}

const errorLogger = async (err, req, res, next) => {
  await logEvents(`\t${err.message} in ${err.fileName}`, err.type);
  next(err)
}

const corsLogger = async (message) => {
  await logEvents(`\t${message}`, 'cors');
}


module.exports = {logEvents, requestLogger, errorLogger, corsLogger}