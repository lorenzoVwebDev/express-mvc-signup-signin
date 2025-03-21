const express = require('express');
const Router = express.Router()
const verifyJWT = require('../../middleware/verifyJWT.js')
const { getAllEmployees, createNewEmployee, updateEmployee, deleteEmployee, getEmployee } = require('../../controller/employees.controller.js')

Router.route('/*')
  .get(/* verifyJWT,  */(req, res, next) => { 
    if (req.query.id === 'ALL') {
      console.log('true')
      getAllEmployees(req, res, next)
    } else {
      getEmployee(req, res, next)
    }
  })
  .post(/* verifyJWT, */ createNewEmployee)
  .put(/* verifyJWT, */ updateEmployee)
  .delete(/* verifyJWT, */ deleteEmployee)

module.exports = Router