const express = require('express');
const Router = express.Router()
const {signUp, signIn, logOut, changePwd} = require('../../controller/authentication.controller.js')

Router.route('/signup').post(signUp);
Router.route('/signin').post(signIn);
Router.route('/logout/*').delete(logOut);
Router.route('/changepwd').put(changePwd);

module.exports = Router