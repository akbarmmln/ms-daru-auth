const Sequelize = require('sequelize');
const dbConnection = require('../config/db').Sequelize;

const adrLogin = (partition) => {
	return dbConnection.define(`adr_login_${partition}`, {
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
		pin: Sequelize.STRING,
		available_counter: Sequelize.INTEGER,
		next_available: Sequelize.DATE,
		blocked: Sequelize.INTEGER,
	}, {
		freezeTableName: true,
		timestamps: false,
		tableName: `adr_login_${partition}`,	
	});
};

module.exports = adrLogin