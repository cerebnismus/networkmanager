import mongoose from 'mongoose';
const Schema = mongoose.Schema;

let date = new Date();
let options = {
	day: "numeric", month: "numeric", year: "numeric",
	hour: "2-digit", minute: "2-digit", second: "2-digit"
};

var datez = date.toLocaleTimeString("en-gb", options).
	replace(/,/, '').
	replace(/ AM/, '').
	replace(/ PM/, '');

  // Wednesday, Oct 25, 2017, 8:19 PM

/* CONTACT MODEL  */
export const ContactSchema = new Schema({
	username: { type: String },
	email: { type: String },
	password: { type: String },
	created_date: {
		type: String,
		default: datez
	}
});

/* DATA MODEL  */
export const DataSchema = new Schema({
	nodename: { type: String },
	sysname: { type: String },
	ipaddress: { type: String },
	community: { type: String },
	port: {
		type: String,
		default: '161'
	},
	vers: {
		type: String,
		default: 'v2c'
	},
	type: {
		type: String,
		default: 'manually'
	},
	subnet: {
		type: String,
		default: 'unknown'
	},
	status: {
		type: String,
		default: '----'
	},
	snmp_status: {
		type: String,
		default: '----'
	},
	oid: {
		type: String,
		default: '1.3.6.1.2.1.1.5.0' //sysname
	},
	created_date: {
		type: String,
		default: datez
	},
	last_poll_date: { // can be time-datez=minute_ago
		type: String,
		default: datez
	}
});

/* DISCO MODEL  */
export const DiscoSchema = new Schema({
	disco_status: {
		type: String,
		default: 'active' 			// to.do : active, inactive, completed
	},
	disco_subnet: { type: String }, 	// to.do : ip or 10.0.0.0/24
	disco_community: { type: String },
	disco_port: {
		type: String,
		default: '161'
	},
	disco_vers: {
		type: String,
		default: 'v2c'
	},
	disco_oid: {
		type: String,
		default: '1.3.6.1.2.1.1.5.0' //sysname
	},
	disco_interval: { 
		type: String,
		default: '60000ms' 				// to.do : 60000ms, 300000ms, 600000ms
	}, 									// to.do : one-time, hourly, daily, weekly, monthly
	disco_created_date: {				// to.do : time-datez=minute_ago
		type: String,
		default: datez
	},
	last_run_date: { 					// to.do : time-datez=minute_ago
		type: String,
		default: datez
	},
    disco_report: { 
		type: String,
		default: 'need to upgrade'
	}
});

/* NODES MODEL  for discovered nodes*/
export const NodeSchema = new Schema({
	node_icmp_status: { type: String },
	node_snmp_status: { type: String },	// to.do : up, down, unknown
	node_subnet: { type: String }, 		// to.do : ip or 10.0.0.0/24
	node_ipaddress: { type: String },	
	node_community: { type: String },	// to.do : public, private
	node_discovered_date: {				// to.do : time-datez=minute_ago
		type: String,
		default: datez
	}
});