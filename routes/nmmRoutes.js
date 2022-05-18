import {
	addNewContact,
	getContacts,
	getContactWithID,
	updateContact,
	deleteContact,
	addNewData,
	getDatas,
	getDataWithID,
	postdeleteData,
	updateData,
	deleteData,
	addNewDisco,
	getDiscos,
	getDiscoWithID,
	postdeleteDisco,
	updateDisco,
	deleteDisco
} from '../controllers/nmmController.js';

const routes = (app) => {

	/* CONTACT ROUTES  */
	app.route('/contact') // to.do /api/v1/contact

		// get endpoint
		.get((req, res, next) => {
			//middleware
			console.log(`Request from: ${req.originalUrl}`)
			console.log(`Request type: ${req.method}`)
			next();
		}, getContacts)

		// post endpoint
		.post(addNewContact);

	/* CONTACT_ID ROUTES  */
	app.route('/contact/:contactID') // to.do /api/v1/contact/:contactID

		// get a specific contact
		.get(getContactWithID)

		// updating a specific contact
		.put(updateContact)

		// deleting a specific contact
		.delete(deleteContact);

	/* DATA ROUTES  */
	app.route('/data') // to.do /api/v1/data
		// get endpoint
		.get((req, res, next) => {
			//middleware
			console.log(`\nGET: endpoint for get all discovery jobs`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			// calls next because it hasn't modified the header
			next();
		}, getDatas)

		// post endpoint
		.post((req, res, next) => {
			// middleware
			console.log(`\nPOST: endpoint for adding new nodes`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request caption: ${req.body.nodename}`)
			console.log(` ⚐ Routes: Request address: ${req.body.ipaddress}`)
			// calls next because it hasn't modified the header
			next();
		}, addNewData)
	
	/* DATA_ID ROUTES  */
	app.route('/data/:dataID') // to.do /api/v1/data/:dataID

		// get a specific data
		.get((req, res, next) => {
			//middleware
			console.log(`\nGET: endpoint for get specific node`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request caption: ${req.body.nodename}`)
			console.log(` ⚐ Routes: Request address: ${req.body.ipaddress}`)
			// calls next because it hasn't modified the header
			next();
		}, getDataWithID)

		// post endpoint for DELETE data method
		// post for deleting a specific data|node
		.post((req, res, next) => {
			//middleware
			console.log(`\nPOST: endpoint for DELETE data method`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request address: ${req.body._id}`)
			// calls next because it hasn't modified the header
			next();
		}, postdeleteData)

		// put endpoint
		// updating a specific data
		.put((req, res, next) => {
			//middleware
			console.log(`\nPUT: endpoint for updating nodes`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request caption: ${req.body.nodename}`)
			console.log(` ⚐ Routes: Request address: ${req.body.ipaddress}`)
			// calls next because it hasn't modified the header
			next();
		}, updateData)

		// delete endpoint
		// deleting a specific data
		.delete((req, res, next) => {
			//middleware
			console.log(`\nDELETE: endpoint for deleting nodes`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request caption: ${req.body.nodename}`)
			console.log(` ⚐ Routes: Request address: ${req.body.ipaddress}`)
			// calls next because it hasn't modified the header
			next();
		}, deleteData)

	/* DISCO ROUTES  */
	app.route('/disco') // to.do /api/v1/disco
		// get endpoint
		.get((req, res, next) => {
			//middleware
			console.log(`\nGET: endpoint for get all discovery jobs`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			// calls next because it hasn't modified the header
			next();
		}, getDiscos)

		// post endpoint
		.post((req, res, next) => {
			// middleware
			console.log(`\nPOST: endpoint for add discovery job`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request descrip: ${req.body.disco_community}`)
			console.log(` ⚐ Routes: Request address: ${req.body.disco_subnet}`)
			// calls next because it hasn't modified the header
			next();
		}, addNewDisco)

	/* DISCO_ID ROUTES  */
	app.route('/disco/:discoID') // to.do /api/v1/disco/:discoID

		// get a specific disco
		.get((req, res, next) => {
			//middleware
			console.log(`\nGET: endpoint for get specific disco`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request descrip: ${req.body.disco_community}`)
			console.log(` ⚐ Routes: Request address: ${req.body.disco_subnet}`)
			// calls next because it hasn't modified the header
			next();
		}, getDiscoWithID)

		// post endpoint for DELETE disco method
		// post for deleting a specific disco
		.post((req, res, next) => {
			//middleware
			console.log(`\nPOST: endpoint for DELETE disco method`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request _id : ${req.body._id}`)
			// calls next because it hasn't modified the header
			next();
		}, postdeleteDisco)

		// put endpoint
		// updating a specific disco
		.put((req, res, next) => {
			//middleware
			console.log(`\nPUT: endpoint for updating a specific disco`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request descrip: ${req.body.disco_community}`)
			console.log(` ⚐ Routes: Request address: ${req.body.disco_subnet}`)
			// calls next because it hasn't modified the header
			next();
		}, updateDisco)

		// delete endpoint
		// deleting a specific disco
		.delete((req, res, next) => {
			//middleware
			console.log(`\nDELETE: endpoint for deleting a specific disco`)
			console.log(` ⚐ Routes: Request from: ${req.originalUrl}`)
			console.log(` ⚐ Routes: Request type: ${req.method}`)
			console.log(` ⚐ Routes: Request descrip: ${req.body.disco_community}`)
			console.log(` ⚐ Routes: Request address: ${req.body.disco_subnet}`)
			// calls next because it hasn't modified the header
			next();
		}, deleteDisco)

};
export default routes;