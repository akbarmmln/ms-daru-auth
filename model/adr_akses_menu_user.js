const Sequelize = require('sequelize');
const dbConnection = require('../config/db').Sequelize;

const adrAksesMenuUser = dbConnection.define('adr_akses_menu_user', {
  id: {
    type: Sequelize.STRING,
    primaryKey: true
  },
  account_id: Sequelize.STRING,
  id_menu: Sequelize.STRING,
  is_deleted: Sequelize.INTEGER
}, {
  freezeTableName: true,
  timestamps: false,
  tableName: 'adr_akses_menu_user'
});

module.exports = adrAksesMenuUser;