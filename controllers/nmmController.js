import mongoose from 'mongoose';
import { ContactSchema } from '../models/nmmModel.js';
import { DataSchema } from '../models/nmmModel.js';
import { DiscoSchema } from '../models/nmmModel.js';
import childprocess from 'child_process';

/*  CONTACT CONTROLLER  */
const Contact = mongoose.model('Contact', ContactSchema);
export const addNewContact = (req, res) => {
	let newContact = new Contact(req.body);

	newContact.save((err, contact) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json(contact);
	});
}
export const getContacts = (req, res) => {
	Contact.find({}, (err, contact) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json(contact);
	});
}
export const getContactWithID = (req, res) => {
	Contact.findById(req.params.contactID, (err, contact) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json(contact);
	});

}
export const updateContact = (req, res) => {
	Contact.findOneAndUpdate({ _id: req.params.contactID }, req.body, { new: true, useFindAndModify: false }, (err, contact) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json(contact);
	});

}
export const deleteContact = (req, res) => {
	Contact.remove({ _id: req.params.contactID }, (err, contact) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json({ message: `succesfully deleted contact: ${_id}` });
	});
}

/* DATA CONTROLLER  */
const Data = mongoose.model("Data", DataSchema);
export const addNewData = (req, res) => {
	// create a new data
	let newData = new Data(req.body);
	let ipData = newData.ipaddress;
	let statusData = newData.status;
	let idData = newData._id;
	
	// caution: do not duplicate data
	Data.countDocuments({ipaddress: ipData}, function (err, count){ 
		if(count>0){
			//document exists });
			console.log(`${ipData}: document exists`);
			// do nothing
		}else{
			//document does not exist
			console.log(`${ipData}: document does not exists`);
			const exec = childprocess.exec;
			exec(`ping -c 1 ${ipData} &> /dev/null && echo 'up' || echo 'down' | head -n1`, (error, stdout, stderr) => {
				if (error) {
					console.log(`error: ${error.message}`);
					return;
				}
				if (stderr) {
					console.log(`stderr: ${stderr}`);
					return;
				}
				console.log(`Controller ping status raw: ${stdout}`);
				newData.save((err, data) => {
					if (err) {
						res.status(500).send(err);
					}
					Data.findOneAndUpdate({ _id: idData }, { $set: { status: stdout } }, { upsert: true, useFindAndModify: false }, (err, data) => {
						// console.log(`Controller ping status last: ${stdout}`);
						res.json(data);
					});
				});
			});
		}
	}); 
}

export const getDatas = (req, res) => {
	Data.find({}, (err, data) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json(data);
	});
}
export const getDataWithID = (req, res) => {
	Data.findById(req.params.dataID, (err, data) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json(data);
	});

}
export const postdeleteData = (req, res) => {
	Data.deleteOne(req.body, (err, data) => {
	// Disco.remove({ _id: req.params.discoID }, (err, data) => {
		if (err) { console.log('res.status(500).send(err);'); }
		// if (err) { res.status(500).send(err); }
		else {
			console.log('POST: deleteOne: ' + data + ' ' + req.body + '\n');
			// reload the page keep post data
			// location.reload();
			res.redirect('/nodes');
		}
		// res.json(data);
	});
}
export const updateData = (req, res) => {
	Data.findOneAndUpdate({ _id: req.params.dataID }, req.body, { new: true, useFindAndModify: false }, (err, data) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json(data);
	});

}
export const deleteData = (req, res) => {
	Data.remove(req.params.dataID, (err, data) => {
		if (err) {
            res.status(500).send(err);
		}
		res.json({ message: `succesfully deleted data: ${_id}` });
	});
}

/* DISCO CONTROLLER  */
const Disco = mongoose.model("Disco", DiscoSchema);
export const addNewDisco = (req, res) => {
	// create a new discoData
	let newDisco = new Disco(req.body);
	let subnetDisco = newDisco.disco_subnet;
	newDisco.save((err, data) => {
		if (err) { res.status(500).send(err); }
		else {
			console.log(`New Discovery Job: ${data}`);			
			// reload the page keep post data
			// location.reload();
			res.redirect('/discovery');
		}
	});
	// const exec = childprocess.exec;
	// exec(`python3.9 polling-discovery.py`, (error, stdout, stderr) => {
	//	if (error) {
	//		console.log(`error: ${error.message}`);
	//		return;
	//	}
	//	if (stderr) {
	//		console.log(`stderr: ${stderr}`);
	//		return;
	//	}
	//	console.log(`polling-discovery is running: \n${stdout}`);
	//});
	//console.log(`polling-discovery is completed \n`);
}

export const getDiscos = (req, res) => {
	Disco.find({}, (err, data) => {
		if (err) { res.status(500).send(err); }
		res.json(data);
	});
}
export const getDiscoWithID = (req, res) => {
	Disco.findById(req.params.discoID, (err, data) => {
		if (err) { res.status(500).send(err); }
		res.json(data);
	});

}
export const postdeleteDisco = (req, res) => {
	Disco.deleteOne(req.body, (err, data) => {
	// Disco.remove({ _id: req.params.discoID }, (err, data) => {
		if (err) { console.log('res.status(500).send(err);'); }
		// if (err) { res.status(500).send(err); }
		else {
			console.log('POST: deleteOne: ' + data + ' ' + req.body + '\n');
			// reload the page keep post data
			// location.reload();
			res.redirect('/discovery');
		}
		// res.json(data);
	});
}
export const updateDisco = (req, res) => {
	Disco.findOneAndUpdate({ _id: req.params.discoID }, req.body, { new: true, useFindAndModify: false }, (err, data) => {
		if (err) { res.status(500).send(err); }
		res.json(data);
	});

}
export const deleteDisco = (req, res) => {
	Disco.remove(req.params.discoID, (err, data) => {
		if (err) { res.status(500).send(err); }
		else {
			console.log(`New Discovery Job: ${data}`);			
			// reload the page keep post data
			// location.reload();
			res.redirect('/discovery');
		}

		// res.json(data);
	});
}