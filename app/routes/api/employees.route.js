const express = require('express');
const Router = express.Router()
const veirifyJWT = require('../../middleware/verifyJWT.js')
const { getAllEmployees, createNewEmployee, updateEmployee, deleteEmployee, getEmployee } = require('../../controller/employees.controller.js')

Router.route('/*')
  .get(veirifyJWT, (req, res, next) => { 
    if (req.query.id === 'ALL') {
      console.log('true')
      getAllEmployees(req, res, next)
    } else {
      getEmployee(req, res, next)
    }
  })
  .post(veirifyJWT, createNewEmployee)
  .put(veirifyJWT, updateEmployee)
  .delete(veirifyJWT, deleteEmployee)

module.exports = Router