const Sequelize = require('sequelize');
const dbConnection = require('../config/db').Sequelize;

const defaultMP = dbConnection.define('default_menu_position', {
  id: {
    type: Sequelize.STRING,
    primaryKey: true
  },
  posititon_id: Sequelize.STRING,
  menu_id: Sequelize.STRING,
  menu_name: Sequelize.STRING,
  activity_name: Sequelize.STRING
}, {
  freezeTableName: true,
  timestamps: false,
  tableName: 'default_menu_position'
});

module.exports = defaultMP;