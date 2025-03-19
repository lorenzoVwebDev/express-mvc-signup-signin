const { v4:uuidv4 } = require('uuid')
const { mysqlQuery, results } = require('../configuration/mysqldb.config.js');
const { errorCreator } = require('../configuration/commonFunctions.js')
const striptags = require('striptags')


const getAllEmployees = async (req, res, next) => {
  try {
    const employees = await new Promise((resolve, reject) => {
      mysqlQuery('select * from ??', ['employees'], resolve, reject);
    }).then(data => data).catch(error => {
      throw new Error(error)
    }) 
  
    res.json(JSON.stringify(employees))

  } catch (err) {
    res.status(500).json({'message': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }
}

const getEmployee = async (req, res, next) => {
  try {
    const { id } = req.query;

    if (!id.toString().match(/^\d*$/)) res.status(400).json({'message':'bad-request'});
 
    const employees = await new Promise((resolve, reject) => {
      mysqlQuery('select * from ??', ['employees'], resolve, reject);
    }).then(data => data).catch(error => {
      throw new Error(error)
    }) 

    let employee = employees.filter(employee => id == employee.id)[0]

    if (!employee) res.status(401).json({'message': 'not-found'});

    res.status(200).json(employee)
    
  } catch (error) {
    res.status(500).json({'message': 'server-error'});
    next(errorCreator(error.message, 'error', __filename));
  }
}

const createNewEmployee = async (req, res, next) => {
  try {
    const employees = await new Promise((resolve, reject) => {
      mysqlQuery('select * from ??', ['employees'], resolve, reject);
    }).then(data => data).catch(error => {
      throw new Error(error)
    }) 


    let { firstname, lastname } = req.body;
    if (!firstname || !lastname) res.status(400).json({'message':'missing-credentials'});
    
    firstname = striptags(firstname);
    lastname = striptags(lastname);

    if (firstname.length > 50 || lastname.length > 50) res.status(401).json({'message':'characters-excess'})
    
    if (firstname.match(/[\W_]/) || lastname.match(/[\W_]/)) res.status(401).json({'message':'invalid-characters'});
  
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

    res.status(200).json({newEmployee})

  } catch (err) {
    res.status(500).json({'message': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }
}

const updateEmployee = async (req, res, next) => {
  try {
    let {id, firstname, lastname } = req.body;

    if (!id.toString().match(/^\d*$/)) res.status(401).json({'message':'invalid-id'});

    firstname = striptags(firstname);
    lastname = striptags(lastname);

    if (firstname.length > 50 || lastname.length > 50) res.status(401).json({'message':'characters-excess'})
    
    if (firstname.match(/[\W_]/) || lastname.match(/[\W_]/)) res.status(401).json({'message':'invalid-characters'});

    const employees = await new Promise((resolve, reject) => {
      mysqlQuery('select * from ??', ['employees'], resolve, reject)
    }).then(data => data).catch(error => {
      throw new Error(error)
    })
    const employee = employees.find(element => element.id === id);

    if (!employee) res.status(401).json({'message':'id-not-found'})
    
    employee.firstname = firstname;
    employee.lastname = lastname;

    await new Promise((resolve, reject) => {
      mysqlQuery('UPDATE ?? SET firstname = ?, lastname = ? WHERE id = ?', ['employees', employee.firstname, employee.lastname, employee.id], resolve, reject)
    }).then(data => data).catch(error => {
      throw new Error(error)
    })
    
    res.status(200).json({'message': `updated-employee${id}`})
  } catch (err) {
    res.status(500).json({'message': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }
}

const deleteEmployee = async (req, res, next) => {
  try {
    const urlArray = req.originalUrl.split('/')
    let id = urlArray[urlArray.length-1];
  
    if (!id.match(/^\d*$/)) res.status(400).json({'message':'invalid-id'});
  
    id = parseInt(id)
  
    const employees = await new Promise((resolve, reject) => {
      mysqlQuery('SELECT * FROM ??', ['employees'], resolve, reject)
    }).then(data => data).catch(error => {
      throw new Error(error)
    })

    const employee = employees.filter(employee => employee.id == id)[0]

    if (!employee) res.status(401).json({'message':'not-found'})

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

    if (deleted) res.status(200).json({'message': `employee${employee.id}-deleted`})
  } catch (err) {
    res.status(500).json({'message': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }



}

module.exports = { getAllEmployees, createNewEmployee, updateEmployee, deleteEmployee, getEmployee }