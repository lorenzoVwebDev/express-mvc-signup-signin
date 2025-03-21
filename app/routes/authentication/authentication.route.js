const express = require('express');
const Router = express.Router()
const {signUp, signIn, logOut} = require('../../controller/authentication.controller.js')

Router.route('/signup').post(signUp);
Router.route('/signin').post(signIn);
Router.route('/logout/*').delete(logOut);

module.exports = Router