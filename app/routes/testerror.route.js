const express = require('express');
const Router = express.Router()
const { logsTest } = require('../controller/logsTest.controller.js')

Router.route('/').get(logsTest)

module.exports = Router