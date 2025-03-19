const express = require('express');
const Router = express.Router()
const { getAllEmployees, createNewEmployee, updateEmployee, deleteEmployee, getEmployee } = require('../../controller/employees.controller.js')

Router.route('/*')
  .get((req, res, next) => { 
    if (req.query.id === 'ALL') {
      console.log('true')
      getAllEmployees(req, res, next)
    } else {
      getEmployee(req, res, next)
    }
  })
  .post(createNewEmployee)
  .put(updateEmployee)
  .delete(deleteEmployee)

module.exports = Router