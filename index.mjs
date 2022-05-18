import routes from './src/routes/nmmRoutes.js';
import bodyParser from 'body-parser';

import express from 'express';
var app = express();
const PORT = 6660;

import dotenv from 'dotenv';
dotenv.config();

import child_process from 'child_process';

// set the mongoClient
import { MongoClient } from 'mongodb';
let db,
    dbConnectionStr = 'mongodb://127.0.0.1:27017',
    dbName = 'test';

MongoClient.connect(dbConnectionStr, { useUnifiedTopology: true })
    .then((client) => {
        console.log(`${dbName} connection succeeded: [mongoclient]`);
        db = client.db(dbName); //connection to database
    })
    .catch((err) => {
        console.error(err);
        console.log('error in DB connection : ' + err);
    });

// set the server
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// bodyparser setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
routes(app);

// serving static files on public folder such as png's
app.use(express.static('public'));

// mongoose connection for rest
import mongoose from 'mongoose';
mongoose.Promise = global.Promise;
mongoose.connect(dbConnectionStr, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}, (err) => {
    if (!err) { console.log(`${dbName} connection succeeded: [mongoose]`); }
    else { console.log('error in DB connection : ' + err); }
});

//start the server
app.listen(process.env.PORT || PORT, () => {
    console.log(`\nserver is running on: [localhost:${PORT}]`);
});

// login page
app.get('/', async (req, res) => {
    res.render('login.ejs');
});

// dashboard page
app.get('/dashboard/', async (req, res) => {
    const dataNotfs = await db.collection('datas').find({"type": "discovered"}).count();
    const dataItems = await db.collection('datas').find().toArray();
    const itemsLeft = await db
        .collection('datas')
        .countDocuments({ completed: false });

    const discoItems = await db.collection('discos').find().toArray();
    const discoItemsLeft = await db
        .collection('discos')
        .countDocuments({ completed: false });

    res.render('dashboard.ejs', {
        dataNotfs: dataNotfs,
        info: dataItems,
        left: itemsLeft,
        disco_info: discoItems,
        disco_left: discoItemsLeft
    });
});

// manage nodes page 
/* you can find the old usages in the view_old folder
        app.get('/managenodes', async (req, res) => {
            // add new node/data
            const exec = child_process.exec;
            exec(`ifconfig -lu | head -n1`, (error, stdout, stderr) => {
                if (error) {
                    console.log(`error: ${error.message}`);
                    return;
                }
                if (stderr) {
                    console.log(`stderr: ${stderr}`);
                    return;
                }
                // console.log(`\nAvailable Interfaces for Polling Engine:`);
                // console.log(`${stdout}`);
                const inets = stdout.split(' ');
                res.render('managenodes.ejs', { inets: inets });
            });
        });      ** end of old route **/

// nodes page
app.get('/nodes', async (req, res) => {
    const dataNotfs = await db.collection('datas').find({"type": "discovered"}).count();
    const dataItems = await db.collection('datas').find().toArray();
    const itemsLeft = await db
        .collection('datas')
        .countDocuments({ completed: false });

    // add new node/data
    const exec = child_process.exec;
	exec(`ifconfig -lu | head -n1`, (error, stdout, stderr) => {
		if (error) {
			console.log(`error: ${error.message}`);
			return;
		}
		if (stderr) {
			console.log(`stderr: ${stderr}`);
			return;
		}
		// console.log(`\nAvailable Interfaces for Polling Engine:`);
		// console.log(`${stdout}`);
        const inets = stdout.split(' ');
        // res.render('managenodes.ejs', { inets: inets });
        res.render('nodes.ejs', {
            dataNotfs: dataNotfs,
            info: dataItems,
            left: itemsLeft,
            inets: inets
        });
    });
});

// network discovery page
app.get('/discovery', async (req, res) => {
    const dataNotfs = await db.collection('datas').find({"type": "discovered"}).count();
    const dataItems = await db.collection('datas').find().toArray();
    const itemsLeft = await db
        .collection('datas')
        .countDocuments({ completed: false });

    const discoItems = await db.collection('discos').find().toArray();
    const discoItemsLeft = await db
        .collection('discos')
        .countDocuments({ completed: false });

    // get INETs for dicovery job
    const exec = child_process.exec;
	exec(`ifconfig -lu | head -n1`, (error, stdout, stderr) => {
		if (error) {
			console.log(`error: ${error.message}`);
			return;
		}
		if (stderr) {
			console.log(`stderr: ${stderr}`);
			return;
		}
		// console.log(`\nAvailable Interfaces for Polling Engine:`);
		// console.log(`${stdout}`);
        const inets = stdout.split(' ');
        // res.render('managenodes.ejs', { inets: inets });
        res.render('discovery.ejs', {
            dataNotfs: dataNotfs,
            info: dataItems,
            disco_info: discoItems,
            disco_left: discoItemsLeft,
            disco_inets: inets
        });
    });
});

// pcap page
app.get('/pcap', async (req, res) => {
    const dataNotfs = await db.collection('datas').find({"type": "discovered"}).count();
    const dataItems = await db.collection('datas').find().toArray();
    const itemsLeft = await db
        .collection('datas')
        .countDocuments({ completed: false });

    // add new node/data
    const exec = child_process.exec;
	exec(`ifconfig -lu | head -n1`, (error, stdout, stderr) => {
		if (error) {
			console.log(`error: ${error.message}`);
			return;
		}
		if (stderr) {
			console.log(`stderr: ${stderr}`);
			return;
		}
		// console.log(`\nAvailable Interfaces for Polling Engine:`);
		// console.log(`${stdout}`);
        const inets = stdout.split(' ');
        // res.render('managenodes.ejs', { inets: inets });
        res.render('pcap.ejs', {
            dataNotfs: dataNotfs,
            info: dataItems,
            left: itemsLeft,
            inets: inets
        });
    });
});

// polling engine
var minutes = 1, the_interval = minutes * 60 * 100;
setInterval(function() {
    const exec = child_process.exec;
    // console.log(`\n Polling Engine Function is running every ${the_interval} miliseconds`);
        exec(`python3.9 polling-engine.py`, (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) {
                console.log(`stderr: ${stderr}`);
                return;
            }
            console.log(`\nPolling Engine Result:`);
            console.log(`----------------------\n${stdout}`);
        });
}, the_interval);

// polling discovery
var minutes = 1, the_interval = minutes * 60 * 100;
setInterval(function() {
    const exec = child_process.exec;
    // console.log(`\n Polling discovery Function is running every ${the_interval} miliseconds`);
        exec(`python3.9 polling-discovery.py`, (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) {
                console.log(`stderr: ${stderr}`);
                return;
            }
            console.log(`\nPolling Discovery Result:`);
            console.log(`-------------------------\n${stdout}`);
        });
}, the_interval);

// notification service