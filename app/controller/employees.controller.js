const { v4:uuidv4 } = require('uuid')
const { mysqlQuery, results } = require('../configuration/mysqldb.config.js');
const { errorCreator } = require('../configuration/commonFunctions.js')
const striptags = require('striptags')
const model = require('../model/employees.model.js')


const getAllEmployees = async (req, res, next) => {
  try {
    const result = await model.modelgetAllEmployees()

    return res.status(result[0]).json(result[1])

  } catch (err) {
    res.status(500).json({'response': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }
}

const getEmployee = async (req, res, next) => {
  try {
    const { id } = req.query;

    const result = await model.modelgetEmployee(id)

    return res.status(result[0]).json(result[1])
    
  } catch (error) {
    res.status(500).json({'response': 'server-error'});
    next(errorCreator(error.message, 'error', __filename));
  }
}

const createNewEmployee = async (req, res, next) => {
  try {
    let { firstname, lastname } = req.body;
    if (!firstname || !lastname) res.status(400).json({'response':'missing-credentials'});

    firstname = striptags(firstname);
    lastname = striptags(lastname);

    
    if (firstname.length > 50 || lastname.length > 50) return res.status(401).json({'response':'characters-excess'})
    
    if (firstname.match(/[\W_]/) || lastname.match(/[\W_]/)) return res.status(401).json({'response':'invalid-characters'});

    const result = await model.modelcreateNewEmployee(firstname, lastname)

    return res.status(result[0]).json(result[1])

  } catch (err) {
    res.status(500).json({'message': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }
}

const updateEmployee = async (req, res, next) => {
  try {
    let {id, firstname, lastname } = req.body;

    if (!id.toString().match(/^\d*$/)) res.status(401).json({'response':'invalid-id'});

    firstname = striptags(firstname);
    lastname = striptags(lastname);

    if (firstname.length > 50 || lastname.length > 50) res.status(401).json({'response':'characters-excess'})
    
    if (firstname.match(/[\W_]/) || lastname.match(/[\W_]/)) res.status(401).json({'response':'invalid-characters'});

    
    const result = await model.modelupdateEmployee(id, firstname, lastname)

    return res.status(result[0]).json(result[1]);

  } catch (err) {
    res.status(500).json({'response': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }
}

const deleteEmployee = async (req, res, next) => {
  try {
    const urlArray = req.originalUrl.split('/')
    let id = urlArray[urlArray.length-1];
  
    if (!id.match(/^\d*$/)) res.status(400).json({'response':'invalid-id'});
  
    id = parseInt(id)
    
    const result = await model.modeldeleteEmployee(id)

    return res.status(result[0]).json(result[1]);

/*     const employees = await new Promise((resolve, reject) => {
      mysqlQuery('SELECT * FROM ??', ['employees'], resolve, reject)
    }).then(data => data).catch(error => {
      throw new Error(error)
    })

    const employee = employees.filter(employee => employee.id == id)[0]

    if (!employee) res.status(401).json({'response':'not-found'})

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

    if (deleted) res.status(200).json({'response': `employee${employee.id}-deleted`}) */
  } catch (err) {
    res.status(500).json({'response': 'server-error'})
    next(errorCreator(err.message, 'error', __filename))
  }



}

module.exports = { getAllEmployees, createNewEmployee, updateEmployee, deleteEmployee, getEmployee }