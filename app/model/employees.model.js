const { v4:uuidv4 } = require('uuid')
const { mysqlQuery, results } = require('../configuration/mysqldb.config.js');
const { errorCreator } = require('../configuration/commonFunctions.js')
const striptags = require('striptags')

const modelgetAllEmployees = async () => {
  const employees = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['employees'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  })
  
  return [200, employees]
}

const modelgetEmployee = async (id) => {
  if (!id.toString().match(/^\d*$/)) res.status(400).json({'response':'bad-request'});
 
  const employees = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['employees'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  }) 

  let employee = employees.filter(employee => id == employee.id)[0]

  if (!employee) return [401, {'response': 'not-found'}];

  return [200, employee]
}

const modelcreateNewEmployee = async (firstname, lastname) => {
  
  const employees = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['employees'], resolve, reject);
  }).then(data => data).catch(error => {
    throw new Error(error)
  }) 

  const newEmployee = {
    id: employees.length > 0 ? employees[employees.length - 1]?.id + 1 : 1,
    firstname,
    lastname
  }
  
  await new Promise((resolve, reject) => {
    mysqlQuery('insert into ?? values (?, ?, ?)', ['employees', newEmployee.id, newEmployee.firstname, newEmployee.lastname], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })

  return [200, newEmployee]
}

const modelupdateEmployee = async (id, firstname, lastname) => {
  const employees = await new Promise((resolve, reject) => {
    mysqlQuery('select * from ??', ['employees'], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })
  const employee = employees.find(element => element.id === id);

  if (!employee) return [401 , {'response':'id-not-found'}]
  
  employee.firstname = firstname;
  employee.lastname = lastname;

  await new Promise((resolve, reject) => {
    mysqlQuery('UPDATE ?? SET firstname = ?, lastname = ? WHERE id = ?', ['employees', employee.firstname, employee.lastname, employee.id], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })
  
  return [200, {'response': `updated-employee${id}`}]
}

const modeldeleteEmployee = async (id) => {
  const employees = await new Promise((resolve, reject) => {
    mysqlQuery('SELECT * FROM ??', ['employees'], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })

  const employee = employees.filter(employee => employee.id == id)[0]

  if (!employee) return [401, {'response':'not-found'}]

  const deleted = await new Promise((resolve, reject) => {
    mysqlQuery('DELETE FROM ?? WHERE id = ?', ['employees', employee.id], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })

  const sorted = await new Promise((resolve, reject) => {
    mysqlQuery('UPDATE ?? SET id = id - 1 WHERE id > ?', ['employees', employee.id], resolve, reject)
  }).then(data => data).catch(error => {
    throw new Error(error)
  })

  if (deleted) return [200, {'response': `employee${employee.id}-deleted`}];
}

module.exports = {modelgetAllEmployees, modelgetEmployee, modelcreateNewEmployee, modelupdateEmployee, modeldeleteEmployee}