const express = require('express');
const Router = express.Router()
const {signUp, signIn} = require('../../controller/authentication.controller.js')

Router.route('/signup').post(signUp);
Router.route('/signin').post(signIn);

module.exports = Router