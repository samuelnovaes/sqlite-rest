const sqlite3 = require('sqlite3').verbose()
const express = require('express')
const bodyParser = require('body-parser')
const jwt = require('jwt-simple')
const cors = require('cors')
const fs = require('fs')
const path = require('path')
const api = require(path.resolve(process.cwd(), process.argv[2]))
const dbFile = path.resolve(path.dirname(process.argv[2]), api.db)
const port = process.argv[3] || 8000
const app = express()
const rets = {
	all: 'all',
	first: 'get',
	none: 'run'
}

app.use(cors())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

for(let route in api){
	if(!/^\w+$/.test(route)){
		for(let method in api[route]){

			let $ret = api[route][method].exec[0]
			let $sql = api[route][method].exec[1]
			let $params = api[route][method].exec[2]
			let $validate = api[route][method].validate
			let $auth = api[route][method].auth

			function cbRequest(req, res){
				if(!$validate || $validate(req)){
					let params = $params ? $params.map(x => {
						let param = x.split('.')
						param.unshift(req)
						return param.reduce((a, b) => a[b])
					}) : []
					let db = new sqlite3.Database(dbFile)
					if($ret == 'token'){
						db.get($sql, params, (err, row) => {
							db.close()
							if(err){
								res.sendStatus(500)
							}
							else if(row){
								res.json(jwt.encode({id: row.id, timeout: api.timeout ? Date.now() + api.timeout : null}, api.secret))
							}
							else {
								res.sendStatus(401)
							}
						})
					}
					else {
						db[rets[$ret]]($sql, params, (err, rows) => {
							db.close()
							if(err){
								res.sendStatus(500)
							}
							else {
								res.json(rows)
							}
						})
					}
				}
				else {
					res.sendStatus(400)
				}
			}

			function authMiddleware(req, res, next){
				let token = req.headers['x-access-token']
				if(token){
					try {
						let decode = jwt.decode(token, api.secret)
						if(decode.timeout && decode.timeout < Date.now()){
							res.sendStatus(401)
						}
						else {
							req.uid = decode.id
							next()
						}
					}
					catch(err){
						res.sendStatus(401)
					}
				}
				else {
					res.sendStatus(401)
				}
			}

			if($auth){
				app[method](route, authMiddleware, cbRequest)
			}
			else {
				app[method](route, cbRequest)
			}

		}
	}
}

let db = new sqlite3.Database(dbFile)
db.exec(api.init, (err) => {
	if(err) throw(err);
	db.close()
	app.listen(port, () => {
		console.log(`API running at http://localhost:${port}`)
	})
})
