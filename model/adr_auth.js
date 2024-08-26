const Sequelize = require('sequelize');
const dbConnection = require('../config/db').Sequelize;

const adrAuth = dbConnection.define('adr_auth', {
  id: {
    type: Sequelize.STRING,
    primaryKey: true
  },
  created_dt: Sequelize.DATE(6),
  created_by: Sequelize.STRING,
  modified_dt: Sequelize.DATE(6),
  modified_by: Sequelize.STRING,
  is_deleted: Sequelize.INTEGER,
  account_id: Sequelize.STRING,
  code: Sequelize.STRING,
  type: Sequelize.STRING,
  validate: Sequelize.INTEGER,
  refresh_token: Sequelize.STRING,
}, {
  freezeTableName: true,
  timestamps: false,
  tableName: 'adr_auth'
});

module.exports = adrAuth;